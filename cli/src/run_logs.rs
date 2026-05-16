use std::{
    collections::BTreeMap,
    fs,
    io::{self, IsTerminal as _, Write as _},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use amber_compiler::run_plan::RunPlan;
use crossterm::{
    queue,
    style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor},
};
use miette::{Context as _, IntoDiagnostic as _, Result};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use tokio::time::sleep;

use crate::{
    mixed_run::{self, PersistedTraceEvent, RunReceipt},
    run_inputs::collect_run_interface,
};

const TRACE_LABEL_WIDTH: usize = 8;
const ACTOR_FIELD_WIDTH: usize = 18;

#[derive(Clone, Copy, Debug)]
pub(crate) struct RunLogOptions {
    pub(crate) follow: bool,
    pub(crate) print_existing: bool,
}

impl Default for RunLogOptions {
    fn default() -> Self {
        Self {
            follow: true,
            print_existing: true,
        }
    }
}

pub(crate) fn print_run_ps(storage_root: &Path, human_output: bool) -> Result<()> {
    let runs_dir = storage_root.join("runs");
    let mut entries = Vec::new();
    if runs_dir.is_dir() {
        for entry in fs::read_dir(&runs_dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to list {}", runs_dir.display()))?
        {
            let entry = entry.into_diagnostic()?;
            let run_root = entry.path();
            let receipt_path = run_root.join("receipt.json");
            if !receipt_path.is_file() {
                continue;
            }
            let receipt: RunReceipt = mixed_run::read_json(&receipt_path, "run receipt")?;
            entries.push(build_run_ps_entry(receipt)?);
        }
    }

    entries.sort_by(|left, right| {
        right
            .sort_started_at_ms
            .cmp(&left.sort_started_at_ms)
            .then_with(|| left.receipt.run_id.cmp(&right.receipt.run_id))
    });
    if entries.is_empty() {
        if !human_output {
            println!("no active runs");
        } else {
            println!("no active runs in {}", storage_root.display());
        }
        return Ok(());
    }

    if !human_output {
        println!("RUN ID\tSITES\tMESH SCOPE\tRUN ROOT");
        for entry in entries {
            println!(
                "{}\t{}\t{}\t{}",
                entry.receipt.run_id,
                entry.receipt.sites.len(),
                entry.receipt.mesh_scope,
                entry.receipt.run_root
            );
        }
        return Ok(());
    }

    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            println!();
        }
        println!(
            "{}  {}  {}  {}  {}",
            entry.receipt.run_id,
            entry.run_status,
            entry.age.as_deref().unwrap_or("?"),
            count_label(entry.receipt.sites.len(), "site"),
            match entry.export_count {
                Some(count) => count_label(count, "export"),
                None => "unknown exports".to_string(),
            }
        );
        println!("  sites: {}", entry.site_labels.join(", "));
        if !entry.attached_exports.is_empty() {
            println!(
                "  exports: {}",
                entry
                    .attached_exports
                    .iter()
                    .map(|(name, url)| format!("{name}={url}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        } else if entry.export_count == Some(0) {
            println!("  exports: none");
        } else if let Some(count) = entry.export_count {
            println!(
                "  exports: {} declared; use `amber attach {}` for localhost URLs",
                count_label(count, "export"),
                entry.receipt.run_id
            );
        } else {
            println!("  exports: unknown");
        }
        println!("  mesh: {}", entry.receipt.mesh_scope);
        println!("  root: {}", entry.receipt.run_root);
    }
    Ok(())
}

pub(crate) fn print_run_logs(run_root: &Path) -> Result<()> {
    let paths = collect_log_files(run_root)?;
    if paths.is_empty() {
        return Err(miette::miette!(
            "run {} has no persisted interaction traces",
            run_root.display()
        ));
    }
    for path in paths {
        let contents = fs::read(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read {}", path.display()))?;
        if contents.is_empty() {
            continue;
        }
        print_log_chunk(run_root, &path, &contents);
    }
    Ok(())
}

pub(crate) async fn stream_run_logs_until(run_root: &Path, options: RunLogOptions) -> Result<()> {
    let mut follower = LogFollower::new(run_root.to_path_buf(), options.print_existing);
    follower.poll_once()?;
    if !options.follow {
        return Ok(());
    }

    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.into_diagnostic().wrap_err("failed to wait for Ctrl-C")?;
                return Ok(());
            }
            _ = sleep(Duration::from_millis(250)) => {
                follower.poll_once()?;
            }
        }
    }
}

struct LogFollower {
    run_root: PathBuf,
    offsets: BTreeMap<PathBuf, usize>,
    print_existing: bool,
}

impl LogFollower {
    fn new(run_root: PathBuf, print_existing: bool) -> Self {
        Self {
            run_root,
            offsets: BTreeMap::new(),
            print_existing,
        }
    }

    fn poll_once(&mut self) -> Result<()> {
        for path in collect_log_files(&self.run_root)? {
            let bytes = fs::read(&path)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read {}", path.display()))?;
            let offset = self
                .offsets
                .entry(path.clone())
                .or_insert_with(|| if self.print_existing { 0 } else { bytes.len() });
            if bytes.len() < *offset {
                *offset = 0;
            }
            if bytes.len() == *offset {
                continue;
            }
            print_log_chunk(&self.run_root, &path, &bytes[*offset..]);
            *offset = bytes.len();
        }
        Ok(())
    }
}

fn collect_log_files(run_root: &Path) -> Result<Vec<PathBuf>> {
    if !run_root.exists() {
        return Err(miette::miette!(
            "run root {} does not exist",
            run_root.display()
        ));
    }
    let events_ndjson = run_root.join("observability").join("events.ndjson");
    if events_ndjson.is_file() {
        return Ok(vec![events_ndjson]);
    }
    let events_log = run_root.join("observability").join("events.log");
    if events_log.is_file() {
        return Ok(vec![events_log]);
    }
    Ok(Vec::new())
}

fn print_log_chunk(_run_root: &Path, path: &Path, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    if path.extension().is_some_and(|ext| ext == "ndjson") {
        let styled = io::stdout().is_terminal();
        if print_structured_trace_chunk(bytes, styled).is_ok() {
            return;
        }
    } else if io::stdout().is_terminal() && print_human_trace_chunk(bytes).is_ok() {
        return;
    }
    print!("{}", String::from_utf8_lossy(bytes));
}

fn print_human_trace_chunk(bytes: &[u8]) -> Result<()> {
    let rendered = String::from_utf8_lossy(bytes);
    let lines = collect_human_trace_lines(&rendered);
    let mut stdout = io::stdout();
    for line in &lines {
        print_human_trace_line(&mut stdout, line)?;
    }
    stdout.flush().into_diagnostic()
}

fn print_structured_trace_chunk(bytes: &[u8], styled: bool) -> Result<()> {
    let rendered = String::from_utf8_lossy(bytes);
    let lines = collect_structured_trace_lines(&rendered)?;
    let mut stdout = io::stdout();
    for line in &lines {
        if styled {
            print_human_trace_line(&mut stdout, line)?;
        } else {
            write!(stdout, "{}", line.plain_text()).into_diagnostic()?;
        }
    }
    stdout.flush().into_diagnostic()
}

fn print_human_trace_line(writer: &mut impl io::Write, line: &HumanTraceLine) -> Result<()> {
    match line {
        HumanTraceLine::Raw(raw) => {
            queue!(writer, Print(&raw.text)).into_diagnostic()?;
        }
        HumanTraceLine::Interaction(interaction) => {
            if let Some(severity) = interaction.severity.as_deref() {
                let severity_color = match severity {
                    "WARN" => Color::Yellow,
                    "ERROR" | "FATAL" => Color::Red,
                    "DEBUG" | "TRACE" => Color::DarkGrey,
                    _ => Color::White,
                };
                print_styled_token(writer, severity, Some(severity_color), &[Attribute::Bold])?;
                queue!(writer, Print("  ")).into_diagnostic()?;
            }

            let trace = interaction
                .trace
                .as_deref()
                .map(short_trace_id)
                .unwrap_or("");
            print_styled_token(
                writer,
                &format!("{trace:TRACE_LABEL_WIDTH$}"),
                Some(Color::DarkGrey),
                &[Attribute::Dim],
            )?;
            queue!(writer, Print("  ")).into_diagnostic()?;

            print_actor_field(writer, &interaction.actor)?;
            print_styled_token(writer, "->", Some(Color::DarkGrey), &[Attribute::Dim])?;
            print_actor_field(writer, &interaction.recipient)?;
            queue!(writer, Print("  ")).into_diagnostic()?;

            let (summary_color, summary_attrs) = if interaction.detail.is_some() {
                (None, &[][..])
            } else {
                (Some(Color::DarkGrey), &[Attribute::Dim][..])
            };
            print_styled_token(
                writer,
                interaction.message_label(),
                summary_color,
                summary_attrs,
            )?;

            if let Some(phase) = interaction.phase {
                queue!(writer, Print("  ")).into_diagnostic()?;
                print_styled_token(
                    writer,
                    phase.badge(),
                    Some(Color::DarkGrey),
                    &[Attribute::Dim],
                )?;
            }

            if let Some(route_badge) = interaction.route_badge() {
                queue!(writer, Print("  ")).into_diagnostic()?;
                print_styled_token(
                    writer,
                    &route_badge,
                    Some(Color::DarkCyan),
                    &[Attribute::Dim],
                )?;
            }

            if interaction.count > 1 {
                queue!(writer, Print("  ")).into_diagnostic()?;
                print_styled_token(
                    writer,
                    &format!("(x{})", interaction.count),
                    Some(Color::DarkGrey),
                    &[Attribute::Dim],
                )?;
            }
        }
    }
    if line.has_newline() {
        queue!(writer, Print("\n")).into_diagnostic()?;
    }
    Ok(())
}

fn split_story_severity(line: &str) -> (Option<&str>, &str) {
    let Some((first, rest)) = line.split_once(' ') else {
        return (None, line);
    };
    match first {
        "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR" | "FATAL" => (Some(first), rest),
        _ => (None, line),
    }
}

fn print_styled_token(
    writer: &mut impl io::Write,
    token: &str,
    color: Option<Color>,
    attributes: &[Attribute],
) -> Result<()> {
    if let Some(color) = color {
        queue!(writer, SetForegroundColor(color)).into_diagnostic()?;
    }
    for attribute in attributes {
        queue!(writer, SetAttribute(*attribute)).into_diagnostic()?;
    }
    queue!(writer, Print(token)).into_diagnostic()?;
    if !attributes.is_empty() {
        queue!(writer, SetAttribute(Attribute::Reset)).into_diagnostic()?;
    }
    if color.is_some() {
        queue!(writer, ResetColor).into_diagnostic()?;
    }
    Ok(())
}

fn print_actor_field(writer: &mut impl io::Write, actor: &str) -> Result<()> {
    let (color, attributes) = if actor.starts_with('/') {
        (Some(Color::Magenta), &[Attribute::Bold][..])
    } else {
        (Some(Color::Yellow), &[Attribute::Bold][..])
    };
    print_styled_token(
        writer,
        &fit_label(actor, ACTOR_FIELD_WIDTH),
        color,
        attributes,
    )
}

fn fit_label(label: &str, width: usize) -> String {
    let label_len = label.chars().count();
    if label_len <= width {
        return format!("{label:<width$}");
    }
    if width <= 6 {
        return label.chars().take(width).collect();
    }
    let left = (width - 3) / 2;
    let right = width - 3 - left;
    let prefix = label.chars().take(left).collect::<String>();
    let suffix = label
        .chars()
        .rev()
        .take(right)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("{prefix}...{suffix}")
}

fn short_trace_id(trace: &str) -> &str {
    trace.get(..TRACE_LABEL_WIDTH).unwrap_or(trace)
}

fn collect_human_trace_lines(rendered: &str) -> Vec<HumanTraceLine> {
    coalesce_human_trace_lines(rendered.split_inclusive('\n').map(HumanTraceLine::parse))
}

fn collect_structured_trace_lines(rendered: &str) -> Result<Vec<HumanTraceLine>> {
    let parsed = rendered
        .split_inclusive('\n')
        .map(structured_trace_line)
        .collect::<Result<Vec<_>>>()?;
    Ok(coalesce_human_trace_lines(parsed))
}

fn structured_trace_line(raw: &str) -> Result<HumanTraceLine> {
    let (text, has_newline) = raw
        .strip_suffix('\n')
        .map_or((raw, false), |trimmed| (trimmed, true));
    if text.trim().is_empty() {
        return Ok(HumanTraceLine::Raw(RawTraceLine {
            text: text.to_string(),
            has_newline,
        }));
    }
    let event: PersistedTraceEvent = serde_json::from_str(text)
        .into_diagnostic()
        .wrap_err("invalid persisted trace event")?;
    Ok(
        NormalizedTraceInteraction::from_persisted_event(&event, has_newline)
            .map(HumanTraceLine::Interaction)
            .unwrap_or_else(|| {
                HumanTraceLine::Raw(RawTraceLine {
                    text: event.message.clone(),
                    has_newline,
                })
            }),
    )
}

fn coalesce_human_trace_lines(
    lines: impl IntoIterator<Item = HumanTraceLine>,
) -> Vec<HumanTraceLine> {
    let mut coalesced = Vec::new();
    let mut pending = None;

    for line in lines {
        match line {
            HumanTraceLine::Raw(raw) => {
                flush_pending_trace_line(&mut pending, &mut coalesced);
                coalesced.push(HumanTraceLine::Raw(raw));
            }
            HumanTraceLine::Interaction(current) => match pending.as_mut() {
                Some(existing) if existing.exact_key() == current.exact_key() => {
                    existing.count += current.count;
                }
                Some(existing)
                    if existing.group_key() == current.group_key()
                        && current.score() > existing.score() =>
                {
                    *existing = current;
                }
                Some(_) => {
                    flush_pending_trace_line(&mut pending, &mut coalesced);
                    pending = Some(current);
                }
                None => pending = Some(current),
            },
        }
    }

    flush_pending_trace_line(&mut pending, &mut coalesced);
    coalesced
}

fn flush_pending_trace_line(
    pending: &mut Option<NormalizedTraceInteraction>,
    lines: &mut Vec<HumanTraceLine>,
) {
    if let Some(line) = pending.take() {
        lines.push(HumanTraceLine::Interaction(line));
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HumanTraceLine {
    Raw(RawTraceLine),
    Interaction(NormalizedTraceInteraction),
}

impl HumanTraceLine {
    fn parse(raw: &str) -> Self {
        let (text, has_newline) = raw
            .strip_suffix('\n')
            .map_or((raw, false), |trimmed| (trimmed, true));
        NormalizedTraceInteraction::parse(text, has_newline)
            .map(Self::Interaction)
            .unwrap_or_else(|| {
                Self::Raw(RawTraceLine {
                    text: text.to_string(),
                    has_newline,
                })
            })
    }

    fn has_newline(&self) -> bool {
        match self {
            Self::Raw(raw) => raw.has_newline,
            Self::Interaction(interaction) => interaction.has_newline,
        }
    }

    fn plain_text(&self) -> String {
        match self {
            Self::Raw(raw) => {
                let mut rendered = raw.text.clone();
                if raw.has_newline {
                    rendered.push('\n');
                }
                rendered
            }
            Self::Interaction(interaction) => interaction.plain_text(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawTraceLine {
    text: String,
    has_newline: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum TracePhase {
    Headers,
    Body,
    Stream,
}

impl TracePhase {
    fn badge(self) -> &'static str {
        match self {
            Self::Headers => "[hdr]",
            Self::Body => "[body]",
            Self::Stream => "[stream]",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TraceMessageKind {
    Request,
    Response,
}

impl TraceMessageKind {
    fn label(self, phase: Option<TracePhase>) -> &'static str {
        match phase {
            Some(TracePhase::Stream) => "event",
            _ => match self {
                Self::Request => "request",
                Self::Response => "response",
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NormalizedTraceInteraction {
    severity: Option<String>,
    actor: String,
    recipient: String,
    kind: TraceMessageKind,
    detail: Option<String>,
    route: Option<String>,
    phase: Option<TracePhase>,
    trace: Option<String>,
    count: usize,
    has_newline: bool,
}

type TraceExactKey<'a> = (
    &'a str,
    &'a str,
    TraceMessageKind,
    Option<&'a str>,
    Option<&'a str>,
    Option<TracePhase>,
    Option<&'a str>,
    Option<&'a str>,
);

type TraceGroupKey<'a> = (
    &'a str,
    &'a str,
    TraceMessageKind,
    Option<&'a str>,
    Option<&'a str>,
);

impl NormalizedTraceInteraction {
    fn parse(line: &str, has_newline: bool) -> Option<Self> {
        let (body, trace) = line
            .rsplit_once(" trace=")
            .map_or((line, None), |(body, trace)| {
                (body, Some(trace.to_string()))
            });
        let (severity, story) = split_story_severity(body);
        let (story, phase) = split_story_phase(story);
        let (story, detail) = story
            .split_once(": ")
            .map_or((story, None), |(story, detail)| {
                (story, Some(detail.to_string()))
            });

        let (actor, recipient, kind, route) =
            parse_story_actors(story).or_else(|| parse_story_receivers(story))?;
        Some(Self {
            severity: severity
                .filter(|severity: &&str| !severity.eq_ignore_ascii_case("info"))
                .map(ToString::to_string),
            actor,
            recipient,
            kind,
            detail,
            route,
            phase,
            trace,
            count: 1,
            has_newline,
        })
    }

    fn from_persisted_event(event: &PersistedTraceEvent, has_newline: bool) -> Option<Self> {
        let kind = trace_kind_for_event(event)?;
        let (actor, recipient) = trace_actor_recipient_for_event(event, kind)?;
        Some(Self {
            severity: event
                .severity
                .as_deref()
                .filter(|severity| !severity.eq_ignore_ascii_case("info"))
                .map(ToString::to_string),
            actor,
            recipient,
            kind,
            detail: structured_trace_detail(event, kind),
            route: trace_route_for_event(event),
            phase: trace_phase_for_event(event),
            trace: event.trace_id.clone(),
            count: 1,
            has_newline,
        })
    }

    fn exact_key(&self) -> TraceExactKey<'_> {
        (
            &self.actor,
            &self.recipient,
            self.kind,
            self.detail.as_deref(),
            self.route.as_deref(),
            self.phase,
            self.trace.as_deref(),
            self.severity.as_deref(),
        )
    }

    fn group_key(&self) -> TraceGroupKey<'_> {
        (
            &self.actor,
            &self.recipient,
            self.kind,
            self.route.as_deref(),
            self.trace.as_deref(),
        )
    }

    fn score(&self) -> (u8, u8) {
        (
            u8::from(self.detail.is_some()),
            self.phase.map_or(0, |phase| match phase {
                TracePhase::Headers => 0,
                TracePhase::Body => 1,
                TracePhase::Stream => 2,
            }),
        )
    }

    fn message_label(&self) -> &str {
        self.detail
            .as_deref()
            .unwrap_or_else(|| self.kind.label(self.phase))
    }

    fn route_badge(&self) -> Option<String> {
        format_route_badge(
            self.route.as_deref()?,
            self.actor.as_str(),
            self.recipient.as_str(),
        )
    }

    fn plain_text(&self) -> String {
        let trace = self.trace.as_deref().map(short_trace_id).unwrap_or("");
        let mut rendered = format!(
            "{trace:TRACE_LABEL_WIDTH$}  {}->{}  {}",
            fit_label(&self.actor, ACTOR_FIELD_WIDTH),
            fit_label(&self.recipient, ACTOR_FIELD_WIDTH),
            self.message_label()
        );
        if let Some(phase) = self.phase {
            rendered.push_str("  ");
            rendered.push_str(phase.badge());
        }
        if let Some(route_badge) = self.route_badge() {
            rendered.push_str("  ");
            rendered.push_str(&route_badge);
        }
        if self.count > 1 {
            rendered.push_str(&format!("  (x{})", self.count));
        }
        if self.has_newline {
            rendered.push('\n');
        }
        rendered
    }
}

fn split_story_phase(story: &str) -> (&str, Option<TracePhase>) {
    if let Some(story) = story.strip_suffix(" [headers]") {
        return (story, Some(TracePhase::Headers));
    }
    if let Some(story) = story.strip_suffix(" [body]") {
        return (story, Some(TracePhase::Body));
    }
    if let Some(story) = story.strip_suffix(" [stream event]") {
        return (story, Some(TracePhase::Stream));
    }
    (story, None)
}

fn parse_story_actors(story: &str) -> Option<(String, String, TraceMessageKind, Option<String>)> {
    let parse_routed = |rest: &str| {
        let (recipient, route) = rest
            .split_once(" via ")
            .map_or((rest, None), |(recipient, route)| (recipient, Some(route)));
        Some((recipient.to_string(), route.map(ToString::to_string)))
    };

    if let Some(rest) = story.strip_prefix("request sent from ") {
        let (actor, rest) = rest.split_once(" to ")?;
        let (recipient, route) = parse_routed(rest)?;
        return Some((
            actor.to_string(),
            recipient,
            TraceMessageKind::Request,
            route,
        ));
    }
    if let Some(rest) = story.strip_prefix("response sent from ") {
        let (actor, rest) = rest.split_once(" to ")?;
        let (recipient, route) = parse_routed(rest)?;
        return Some((
            actor.to_string(),
            recipient,
            TraceMessageKind::Response,
            route,
        ));
    }
    if let Some(rest) = story.strip_prefix("request received from ") {
        let (actor, recipient) = rest.split_once(" by ")?;
        return Some((
            actor.to_string(),
            recipient.to_string(),
            TraceMessageKind::Request,
            None,
        ));
    }
    None
}

fn parse_story_receivers(
    story: &str,
) -> Option<(String, String, TraceMessageKind, Option<String>)> {
    let parse_routed = |rest: &str| {
        let (actor, route) = rest
            .split_once(" via ")
            .map_or((rest, None), |(actor, route)| (actor, Some(route)));
        Some((actor.to_string(), route.map(ToString::to_string)))
    };

    if let Some(rest) = story.strip_prefix("request received by ") {
        let (recipient, rest) = rest.split_once(" from ")?;
        let (actor, route) = parse_routed(rest)?;
        return Some((
            actor,
            recipient.to_string(),
            TraceMessageKind::Request,
            route,
        ));
    }
    if let Some(rest) = story.strip_prefix("response received by ") {
        let (recipient, rest) = rest.split_once(" from ")?;
        let (actor, route) = parse_routed(rest)?;
        return Some((
            actor,
            recipient.to_string(),
            TraceMessageKind::Response,
            route,
        ));
    }
    None
}

fn format_route_badge(route: &str, actor: &str, recipient: &str) -> Option<String> {
    let (source, destination) = route.split_once(" -> ")?;
    let source_endpoint = source.strip_prefix(actor)?.strip_prefix('.')?;
    let destination_endpoint = destination.strip_prefix(recipient)?.strip_prefix('.')?;
    if source_endpoint == destination_endpoint {
        return Some(format!("@{source_endpoint}"));
    }
    Some(format!("@{source_endpoint}->{destination_endpoint}"))
}

fn trace_kind_for_event(event: &PersistedTraceEvent) -> Option<TraceMessageKind> {
    let stage = event_attr_str(event, "amber_lifecycle_stage")?;
    Some(if stage.ends_with("request") {
        TraceMessageKind::Request
    } else if stage.ends_with("response") {
        TraceMessageKind::Response
    } else {
        return None;
    })
}

fn trace_actor_recipient_for_event(
    event: &PersistedTraceEvent,
    kind: TraceMessageKind,
) -> Option<(String, String)> {
    let source = event_party_label(
        event,
        "amber_source_component",
        "amber_source_ref",
        "amber_source_endpoint",
    )?;
    let destination = event_party_label(
        event,
        "amber_destination_component",
        "amber_destination_ref",
        "amber_destination_endpoint",
    )?;
    Some(match kind {
        TraceMessageKind::Request => (source, destination),
        TraceMessageKind::Response => (destination, source),
    })
}

fn event_party_label(
    event: &PersistedTraceEvent,
    component_key: &str,
    ref_key: &str,
    endpoint_key: &str,
) -> Option<String> {
    event_attr_str(event, component_key)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            event_attr_str(event, ref_key)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
        })
        .or_else(|| {
            event_attr_str(event, endpoint_key)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
        })
}

fn trace_phase_for_event(event: &PersistedTraceEvent) -> Option<TracePhase> {
    match event_attr_str(event, "amber_exchange_step")? {
        "headers" => Some(TracePhase::Headers),
        "body" => Some(TracePhase::Body),
        "stream_event" => Some(TracePhase::Stream),
        _ => None,
    }
}

fn trace_route_for_event(event: &PersistedTraceEvent) -> Option<String> {
    event_attr_str(event, "amber_edge_ref")
        .filter(|route| route.contains(" -> "))
        .map(ToString::to_string)
}

fn structured_trace_detail(event: &PersistedTraceEvent, kind: TraceMessageKind) -> Option<String> {
    let mut detail = if let Some(detail) = event_attr_str(event, "amber_a2a_task_state")
        .map(humanize_task_state)
        .map(|state| format!("task {state}"))
    {
        let mut detail = detail;
        if let Some(task_id) = event_attr_str(event, "amber_a2a_task_id") {
            detail.push_str(&format!(" task={}", compact_value(task_id, 16)));
        }
        if let Some(count) =
            event_attr_i64(event, "amber_a2a_artifact_count").filter(|count| *count > 0)
        {
            detail.push_str(&format!(" artifacts={count}"));
        }
        detail
    } else if let Some(progress) = event_attr_f64(event, "amber_mcp_progress") {
        let mut detail = if let Some(total) = event_attr_f64(event, "amber_mcp_progress_total") {
            format!(
                "progress {}/{}",
                format_decimal(progress),
                format_decimal(total)
            )
        } else {
            format!("progress {}", format_decimal(progress))
        };
        if let Some(message) = event_attr_str(event, "amber_mcp_progress_message") {
            detail.push_str(&format!(" ({})", compact_value(message, 28)));
        }
        detail
    } else if let Some(method) = event_attr_str(event, "amber_rpc_method") {
        let mut detail = humanize_method_detail(method);
        if method == "tools/call" {
            if let Some(tool_name) = event_attr_str(event, "amber_mcp_tool_name") {
                detail.push_str(&format!(" {}", compact_value(tool_name, 24)));
            }
        } else if method.starts_with("resources/")
            && let Some(resource_uri) = event_attr_str(event, "amber_mcp_resource_uri")
        {
            detail.push_str(&format!(" {}", compact_value(resource_uri, 32)));
        }
        if kind == TraceMessageKind::Request
            && event_attr_str(event, "amber_rpc_kind") == Some("notification")
        {
            detail.push_str(" notification");
        }
        if kind == TraceMessageKind::Response {
            if event_attr_bool(event, "amber_application_error") == Some(true) {
                detail.push_str(" error");
            } else if event_attr_str(event, "amber_rpc_kind") == Some("result") {
                detail.push_str(" result");
            } else {
                detail.push_str(" response");
            }
        }
        detail
    } else if let Some(subject) = event_attr_str(event, "amber_http_subject") {
        subject.to_string()
    } else {
        return None;
    };

    if let Some(message_id) = event_attr_str(event, "amber_a2a_message_id") {
        detail.push_str(&format!(" msg={}", compact_value(message_id, 16)));
    }
    if let Some(context_id) = event_attr_str(event, "amber_a2a_context_id") {
        detail.push_str(&format!(" ctx={}", compact_value(context_id, 16)));
    }
    if let Some(rpc_id) = event_attr_str(event, "amber_rpc_id")
        && event_attr_str(event, "amber_a2a_message_id").is_none()
        && event_attr_str(event, "amber_a2a_task_id").is_none()
    {
        detail.push_str(&format!(" (id={})", compact_value(rpc_id, 20)));
    }

    Some(detail)
}

fn event_attr_str<'a>(event: &'a PersistedTraceEvent, key: &str) -> Option<&'a str> {
    match event.attributes.get(key)? {
        JsonValue::String(value) => (!value.is_empty()).then_some(value.as_str()),
        _ => None,
    }
}

fn event_attr_bool(event: &PersistedTraceEvent, key: &str) -> Option<bool> {
    match event.attributes.get(key)? {
        JsonValue::Bool(value) => Some(value.to_owned()),
        _ => None,
    }
}

fn event_attr_i64(event: &PersistedTraceEvent, key: &str) -> Option<i64> {
    match event.attributes.get(key)? {
        JsonValue::Number(value) => value.as_i64(),
        _ => None,
    }
}

fn event_attr_f64(event: &PersistedTraceEvent, key: &str) -> Option<f64> {
    match event.attributes.get(key)? {
        JsonValue::Number(value) => value.as_f64(),
        _ => None,
    }
}

fn humanize_method_detail(method: &str) -> String {
    if let Some((family, action)) = method.split_once('/') {
        return humanize_slash_method(family, action);
    }
    humanize_identifier(method)
}

fn humanize_slash_method(family: &str, action: &str) -> String {
    let action = humanize_identifier(action);
    let family_plural = humanize_identifier(family);
    let family_singular = singularize_phrase(&family_plural);

    if family == "notifications" {
        return match action.as_str() {
            "progress" => "progress update".to_string(),
            "message" => "log message".to_string(),
            _ => format!("{action} notification"),
        };
    }

    if action == "list" {
        return format!("list {family_plural}");
    }

    format!("{action} {family_singular}")
}

fn singularize_phrase(phrase: &str) -> String {
    let Some((prefix, last)) = phrase.rsplit_once(' ') else {
        return singularize_word(phrase).to_string();
    };
    format!("{prefix} {}", singularize_word(last))
}

fn singularize_word(word: &str) -> &str {
    if word.len() > 1 && word.ends_with('s') {
        &word[..word.len() - 1]
    } else {
        word
    }
}

fn humanize_task_state(state: &str) -> String {
    humanize_identifier(state.trim_start_matches("TASK_STATE_"))
}

fn humanize_identifier(input: &str) -> String {
    let chars = input.chars().collect::<Vec<_>>();
    let mut words = Vec::new();
    let mut current = String::new();
    let mut previous_was_lower_or_digit = false;
    let mut previous_was_upper = false;

    for (index, ch) in chars.iter().enumerate() {
        if !ch.is_ascii_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            previous_was_lower_or_digit = false;
            previous_was_upper = false;
            continue;
        }

        let next_is_lower = chars
            .get(index + 1)
            .is_some_and(|next| next.is_ascii_lowercase());
        let starts_new_word = !current.is_empty()
            && ((previous_was_lower_or_digit && ch.is_ascii_uppercase())
                || (previous_was_upper && ch.is_ascii_uppercase() && next_is_lower));
        if starts_new_word {
            words.push(std::mem::take(&mut current));
        }

        current.push(ch.to_ascii_lowercase());
        previous_was_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        previous_was_upper = ch.is_ascii_uppercase();
    }

    if !current.is_empty() {
        words.push(current);
    }

    words.join(" ")
}

fn compact_value(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    if max_chars <= 6 {
        return value.chars().take(max_chars).collect();
    }
    let left = (max_chars - 3) / 2;
    let right = max_chars - 3 - left;
    let prefix = value.chars().take(left).collect::<String>();
    let suffix = value
        .chars()
        .rev()
        .take(right)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("{prefix}...{suffix}")
}

fn format_decimal(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{}", value as i64)
    } else {
        format!("{value:.2}")
    }
}

#[derive(Debug, Deserialize)]
struct StoredSiteState {
    status: String,
}

#[derive(Debug, Deserialize)]
struct StoredOutsideProxyState {
    #[serde(default)]
    exports: BTreeMap<String, String>,
}

struct RunPsEntry {
    receipt: RunReceipt,
    run_status: String,
    age: Option<String>,
    site_labels: Vec<String>,
    export_count: Option<usize>,
    attached_exports: BTreeMap<String, String>,
    sort_started_at_ms: Option<u128>,
}

fn build_run_ps_entry(receipt: RunReceipt) -> Result<RunPsEntry> {
    let run_root = PathBuf::from(&receipt.run_root);
    let site_details = receipt
        .sites
        .iter()
        .map(|(site_id, site)| {
            let state_path = run_root
                .join("state")
                .join(site_id)
                .join("manager-state.json");
            let status = if state_path.is_file() {
                Some(
                    mixed_run::read_json::<StoredSiteState>(&state_path, "site manager state")?
                        .status,
                )
            } else {
                None
            };
            Ok((site_id.clone(), site.kind, status))
        })
        .collect::<Result<Vec<_>>>()?;
    let run_status = aggregate_run_status(&site_details);
    let site_labels = site_details
        .into_iter()
        .map(|(site_id, kind, status)| format_site_label(&site_id, kind, status.as_deref()))
        .collect::<Vec<_>>();
    let export_count = load_export_count(&run_root)?;
    let attached_exports = load_attached_exports(&run_root)?;
    let sort_started_at_ms = run_started_at_ms(&receipt.run_id);
    let age = format_run_age(sort_started_at_ms);
    Ok(RunPsEntry {
        receipt,
        run_status,
        age,
        site_labels,
        export_count,
        attached_exports,
        sort_started_at_ms,
    })
}

fn load_export_count(run_root: &Path) -> Result<Option<usize>> {
    let run_plan_path = run_root.join("run-plan.json");
    if !run_plan_path.is_file() {
        return Ok(None);
    }
    let run_plan: RunPlan = mixed_run::read_json(&run_plan_path, "run plan")?;
    Ok(Some(collect_run_interface(&run_plan)?.exports.len()))
}

fn load_attached_exports(run_root: &Path) -> Result<BTreeMap<String, String>> {
    let state_path = run_root.join("outside-proxy-state.json");
    if !state_path.is_file() {
        return Ok(BTreeMap::new());
    }
    Ok(
        mixed_run::read_json::<StoredOutsideProxyState>(&state_path, "outside proxy state")?
            .exports,
    )
}

fn aggregate_run_status(
    site_details: &[(String, amber_compiler::run_plan::SiteKind, Option<String>)],
) -> String {
    let known = site_details
        .iter()
        .filter_map(|(_, _, status)| status.as_deref())
        .collect::<Vec<_>>();
    if known.is_empty() {
        return "unknown".to_string();
    }
    if known.contains(&"failed") {
        return "failed".to_string();
    }
    if known.contains(&"stopping") {
        return "stopping".to_string();
    }
    if known.contains(&"starting") {
        return "starting".to_string();
    }
    if known.iter().all(|status| *status == "running") {
        return "running".to_string();
    }
    if known.iter().all(|status| *status == "stopped") {
        return "stopped".to_string();
    }
    if known.contains(&"running") {
        return "degraded".to_string();
    }
    "unknown".to_string()
}

fn format_site_label(
    site_id: &str,
    kind: amber_compiler::run_plan::SiteKind,
    status: Option<&str>,
) -> String {
    let kind = format!("{kind:?}").to_ascii_lowercase();
    match status {
        Some("running") | None => format!("{site_id} ({kind})"),
        Some(status) => format!("{site_id} ({kind}, {status})"),
    }
}

fn run_started_at_ms(run_id: &str) -> Option<u128> {
    let raw = run_id.strip_prefix("run-")?;
    let (started_hex, _) = raw.split_once('-')?;
    u128::from_str_radix(started_hex, 16).ok()
}

fn format_run_age(started_at_ms: Option<u128>) -> Option<String> {
    let started_at_ms = started_at_ms?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    let age_secs = now_ms.saturating_sub(started_at_ms) / 1000;
    Some(if age_secs < 60 {
        format!("{age_secs}s")
    } else if age_secs < 60 * 60 {
        format!("{}m", age_secs / 60)
    } else if age_secs < 60 * 60 * 24 {
        format!("{}h", age_secs / (60 * 60))
    } else {
        format!("{}d", age_secs / (60 * 60 * 24))
    })
}

fn count_label(count: usize, singular: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {singular}s")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ACTOR_FIELD_WIDTH, TRACE_LABEL_WIDTH, collect_human_trace_lines, fit_label, short_trace_id,
    };

    fn render_plain(input: &str) -> String {
        collect_human_trace_lines(input)
            .into_iter()
            .map(|line| line.plain_text())
            .collect()
    }

    #[test]
    fn human_trace_renderer_normalizes_to_actor_recipient_flow() {
        let rendered =
            render_plain("request received from a2a by /runtime [headers] trace=abc123\n");
        assert_eq!(
            rendered,
            format!(
                "{:TRACE_LABEL_WIDTH$}  {}->{}  request  [hdr]\n",
                short_trace_id("abc123"),
                fit_label("a2a", ACTOR_FIELD_WIDTH),
                fit_label("/runtime", ACTOR_FIELD_WIDTH),
            )
        );
    }

    #[test]
    fn human_trace_renderer_dedupes_mirror_lines_and_keeps_richer_detail() {
        let rendered = render_plain(
            "request sent from /runtime to /auth_proxy via /runtime.responses_api -> \
             /auth_proxy.responses_api [headers] trace=abc123\nrequest received by /auth_proxy \
             from /runtime via /runtime.responses_api -> /auth_proxy.responses_api [headers] \
             trace=abc123\nrequest sent from /runtime to /auth_proxy via /runtime.responses_api \
             -> /auth_proxy.responses_api: initialize (id=0) [body] trace=abc123\n",
        );
        assert_eq!(
            rendered,
            format!(
                "{:TRACE_LABEL_WIDTH$}  {}->{}  initialize (id=0)  [body]  @responses_api\n",
                short_trace_id("abc123"),
                fit_label("/runtime", ACTOR_FIELD_WIDTH),
                fit_label("/auth_proxy", ACTOR_FIELD_WIDTH),
            )
        );
    }

    #[test]
    fn human_trace_renderer_collapses_identical_adjacent_events() {
        let rendered = render_plain(
            "response sent from /runtime to a2a [stream event] trace=abc123\nresponse sent from \
             /runtime to a2a [stream event] trace=abc123\nresponse sent from /runtime to a2a \
             [stream event] trace=abc123\n",
        );
        assert_eq!(
            rendered,
            format!(
                "{:TRACE_LABEL_WIDTH$}  {}->{}  event  [stream]  (x3)\n",
                short_trace_id("abc123"),
                fit_label("/runtime", ACTOR_FIELD_WIDTH),
                fit_label("a2a", ACTOR_FIELD_WIDTH),
            )
        );
    }
}
