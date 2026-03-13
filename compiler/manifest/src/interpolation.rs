use std::{fmt, str::FromStr};

use jsonptr::PointerBuf;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{
        MapAccess, SeqAccess, Visitor,
        value::{MapAccessDeserializer, SeqAccessDeserializer},
    },
};
use serde_json::Value;
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::{Error, SlotTarget, parse_slot_query};

#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    DeserializeFromStr,
    SerializeDisplay,
)]
#[non_exhaustive]
pub struct InterpolatedString {
    pub parts: Vec<InterpolatedPart>,
}

impl InterpolatedString {
    pub fn from_literal(value: impl Into<String>) -> Self {
        Self {
            parts: vec![InterpolatedPart::Literal(value.into())],
        }
    }

    pub fn as_literal(&self) -> Option<&str> {
        match self.parts.as_slice() {
            [InterpolatedPart::Literal(value)] => Some(value.as_str()),
            _ => None,
        }
    }

    /// Visit slot names referenced by `${slots...}` interpolations.
    ///
    /// The visited slot name is the first query segment (e.g. `${slots.llm.url}` visits `llm`).
    /// Returns `true` if the interpolation references all slots (e.g. `${slots}`).
    pub fn visit_slot_uses(&self, mut visit: impl FnMut(&str)) -> bool {
        for part in &self.parts {
            let InterpolatedPart::Interpolation { source, query } = part else {
                continue;
            };
            if *source != InterpolationSource::Slots {
                continue;
            }
            if query.is_empty() {
                return true;
            }
            let slot = query
                .split_once('.')
                .map_or(query.as_str(), |(first, _)| first);
            if slot.is_empty() {
                return false;
            }
            visit(slot);
        }
        false
    }
}

impl From<String> for InterpolatedString {
    fn from(value: String) -> Self {
        Self::from_literal(value)
    }
}

impl From<&str> for InterpolatedString {
    fn from(value: &str) -> Self {
        Self::from_literal(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum InterpolatedPart {
    Literal(String),
    Interpolation {
        source: InterpolationSource,
        query: String,
    },
}

impl FromStr for InterpolatedPart {
    type Err = Error;

    fn from_str(inner: &str) -> Result<Self, Error> {
        if inner.is_empty() {
            return Err(Error::InvalidInterpolation(inner.to_string()));
        }

        let (prefix, query) = inner
            .split_once('.')
            .map_or((inner, ""), |(prefix, query)| (prefix, query));

        let source = match prefix {
            "config" => InterpolationSource::Config,
            "slots" => InterpolationSource::Slots,
            "item" => InterpolationSource::Item,
            _ => return Err(Error::InvalidInterpolation(inner.to_string())),
        };

        Ok(InterpolatedPart::Interpolation {
            source,
            query: query.to_string(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum InterpolationSource {
    Config,
    Slots,
    Item,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRefSpec {
    pub file: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(untagged)]
pub enum InlineStringSpec {
    Inline(String),
    File(FileRefSpec),
}

impl<'de> Deserialize<'de> for InlineStringSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Value::deserialize(deserializer)? {
            Value::String(value) => {
                value
                    .parse::<InterpolatedString>()
                    .map_err(serde::de::Error::custom)?;
                Ok(Self::Inline(value))
            }
            Value::Object(map) => serde_json::from_value::<FileRefSpec>(Value::Object(map))
                .map(Self::File)
                .map_err(serde::de::Error::custom),
            _ => Err(serde::de::Error::custom(
                "expected a string or a `{ file: ... }` reference",
            )),
        }
    }
}

impl From<String> for InlineStringSpec {
    fn from(value: String) -> Self {
        Self::Inline(value)
    }
}

impl From<InterpolatedString> for InlineStringSpec {
    fn from(value: InterpolatedString) -> Self {
        Self::Inline(value.to_string())
    }
}

impl From<&str> for InlineStringSpec {
    fn from(value: &str) -> Self {
        Self::Inline(value.to_string())
    }
}

impl fmt::Display for InterpolationSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            InterpolationSource::Config => "config",
            InterpolationSource::Slots => "slots",
            InterpolationSource::Item => "item",
        };
        f.write_str(s)
    }
}

impl FromStr for InterpolatedString {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut parts = Vec::new();
        let mut current_literal = String::new();
        let mut chars = input.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '$' && chars.peek() == Some(&'{') {
                chars.next(); // consume '{'
                if !current_literal.is_empty() {
                    parts.push(InterpolatedPart::Literal(std::mem::take(
                        &mut current_literal,
                    )));
                }

                let mut inner = String::new();
                let mut closed = false;
                for ic in chars.by_ref() {
                    if ic == '}' {
                        closed = true;
                        break;
                    }
                    inner.push(ic);
                }

                if !closed {
                    return Err(Error::InvalidInterpolation(input.to_string()));
                }
                parts.push(inner.parse()?);
            } else {
                current_literal.push(c);
            }
        }

        if !current_literal.is_empty() {
            parts.push(InterpolatedPart::Literal(current_literal));
        }

        Ok(Self { parts })
    }
}

impl fmt::Display for InterpolatedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for part in &self.parts {
            match part {
                InterpolatedPart::Literal(s) => f.write_str(s)?,
                InterpolatedPart::Interpolation { source, query } => {
                    f.write_str("${")?;
                    write!(f, "{source}")?;
                    if !query.is_empty() {
                        f.write_str(".")?;
                        f.write_str(query)?;
                    }
                    f.write_str("}")?;
                }
            }
        }
        Ok(())
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, DeserializeFromStr, SerializeDisplay,
)]
pub struct WhenPath {
    source: InterpolationSource,
    query: String,
}

impl WhenPath {
    pub fn source(&self) -> InterpolationSource {
        self.source
    }

    pub fn query(&self) -> &str {
        &self.query
    }
}

impl fmt::Display for WhenPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.source)?;
        if !self.query.is_empty() {
            write!(f, ".{}", self.query)?;
        }
        Ok(())
    }
}

impl FromStr for WhenPath {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let InterpolatedPart::Interpolation { source, query } = input.parse()? else {
            unreachable!("when path parser never returns literals");
        };

        match source {
            InterpolationSource::Config => validate_config_when_path(input, &query)?,
            InterpolationSource::Slots => validate_slot_when_path(input, &query)?,
            InterpolationSource::Item => {
                return Err(Error::InvalidWhenPath {
                    input: input.to_string(),
                    message: "expected `config.<path>` or `slots.<path>`".to_string(),
                });
            }
        }
        Ok(Self { source, query })
    }
}

fn validate_config_when_path(input: &str, query: &str) -> Result<(), Error> {
    if !query.is_empty() && !query.split('.').any(str::is_empty) {
        return Ok(());
    }

    Err(Error::InvalidWhenPath {
        input: input.to_string(),
        message: "expected `config.<path>` or `slots.<path>`".to_string(),
    })
}

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, DeserializeFromStr, SerializeDisplay,
)]
pub struct EachPath {
    source: InterpolationSource,
    query: String,
}

impl EachPath {
    pub fn source(&self) -> InterpolationSource {
        self.source
    }

    pub fn query(&self) -> &str {
        &self.query
    }

    pub fn slot(&self) -> Option<&str> {
        (self.source == InterpolationSource::Slots).then_some(self.query.as_str())
    }

    pub fn config_path(&self) -> Option<&str> {
        (self.source == InterpolationSource::Config).then_some(self.query.as_str())
    }
}

impl fmt::Display for EachPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.source, self.query)
    }
}

impl FromStr for EachPath {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (source, query) = input
            .split_once('.')
            .map_or((input, ""), |(source, query)| (source, query));
        let source = match source {
            "config" => InterpolationSource::Config,
            "slots" => InterpolationSource::Slots,
            _ => {
                return Err(Error::InvalidEachPath {
                    input: input.to_string(),
                    message: "expected `config.<path>` or `slots.<slot>`".to_string(),
                });
            }
        };

        if query.is_empty() || query.split('.').any(str::is_empty) {
            return Err(Error::InvalidEachPath {
                input: input.to_string(),
                message: "expected `config.<path>` or `slots.<slot>`".to_string(),
            });
        }

        if source == InterpolationSource::Slots && query.contains('.') {
            return Err(Error::InvalidEachPath {
                input: input.to_string(),
                message: "expected `config.<path>` or `slots.<slot>`".to_string(),
            });
        }

        Ok(Self {
            source,
            query: query.to_string(),
        })
    }
}

fn validate_slot_when_path(input: &str, query: &str) -> Result<(), Error> {
    let parsed = parse_slot_query(query).map_err(|err| Error::InvalidWhenPath {
        input: input.to_string(),
        message: err.to_string(),
    })?;

    if matches!(parsed.target, SlotTarget::Slot(_)) {
        return Ok(());
    }

    Err(Error::InvalidWhenPath {
        input: input.to_string(),
        message: "expected `config.<path>` or `slots.<path>`".to_string(),
    })
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ProgramArgList(pub Vec<InterpolatedString>);

impl ProgramArgList {
    pub fn iter(&self) -> impl Iterator<Item = &InterpolatedString> {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de> Deserialize<'de> for ProgramArgList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_program_arg_list(deserializer).map(Self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProgramArgValue {
    Arg(InterpolatedString),
    Argv(ProgramArgList),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProgramArgItem {
    pub when: Option<WhenPath>,
    pub each: Option<EachPath>,
    pub value: ProgramArgValue,
    pub join: Option<String>,
}

impl ProgramArgItem {
    pub fn arg(&self) -> Option<&InterpolatedString> {
        match &self.value {
            ProgramArgValue::Arg(arg) => Some(arg),
            ProgramArgValue::Argv(_) => None,
        }
    }

    pub fn argv(&self) -> Option<&ProgramArgList> {
        match &self.value {
            ProgramArgValue::Arg(_) => None,
            ProgramArgValue::Argv(argv) => Some(argv),
        }
    }

    pub fn when(&self) -> Option<&WhenPath> {
        self.when.as_ref()
    }

    pub fn each(&self) -> Option<&EachPath> {
        self.each.as_ref()
    }

    pub fn is_repeated(&self) -> bool {
        self.each.is_some()
    }

    pub fn join(&self) -> Option<&str> {
        self.join.as_deref()
    }

    pub fn field_name(&self) -> &'static str {
        match self.value {
            ProgramArgValue::Arg(_) => "arg",
            ProgramArgValue::Argv(_) => "argv",
        }
    }

    pub fn visit_values(&self, mut visit: impl FnMut(&InterpolatedString)) {
        match &self.value {
            ProgramArgValue::Arg(arg) => visit(arg),
            ProgramArgValue::Argv(argv) => {
                for arg in &argv.0 {
                    visit(arg);
                }
            }
        }
    }

    /// Visit slot names referenced by this program arg item, including `when` conditions and
    /// repeated `each` selectors. Returns `true` if the item references all slots.
    pub fn visit_slot_uses(&self, mut visit: impl FnMut(&str)) -> bool {
        if let Some(when) = self.when()
            && visit_when_slot_uses(when, &mut visit)
        {
            return true;
        }

        if let Some(each) = self.each()
            && each.source() == InterpolationSource::Slots
            && let Some(slot) = each.slot()
        {
            visit(slot);
        }

        match &self.value {
            ProgramArgValue::Arg(arg) => arg.visit_slot_uses(visit),
            ProgramArgValue::Argv(argv) => visit_program_arg_list_slot_uses(argv, &mut visit),
        }
    }

    fn validate(&self) -> Result<(), String> {
        match (self.each.as_ref(), &self.value, self.join.as_ref()) {
            (None, _, Some(_)) => Err("`join` is only valid with `each` and `arg`".to_string()),
            (Some(_), ProgramArgValue::Argv(_), Some(_)) => {
                Err("`join` is only valid with `each` and `arg`".to_string())
            }
            _ => Ok(()),
        }
    }
}

impl From<InterpolatedString> for ProgramArgItem {
    fn from(value: InterpolatedString) -> Self {
        Self {
            when: None,
            each: None,
            value: ProgramArgValue::Arg(value),
            join: None,
        }
    }
}

impl Serialize for ProgramArgItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.when.is_none()
            && self.each.is_none()
            && self.join.is_none()
            && let ProgramArgValue::Arg(arg) = &self.value
        {
            return arg.serialize(serializer);
        }

        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(None)?;
        if let Some(when) = &self.when {
            map.serialize_entry("when", when)?;
        }
        if let Some(each) = &self.each {
            map.serialize_entry("each", each)?;
        }
        if let Some(join) = &self.join {
            map.serialize_entry("join", join)?;
        }
        match &self.value {
            ProgramArgValue::Arg(arg) => map.serialize_entry("arg", arg)?,
            ProgramArgValue::Argv(argv) => map.serialize_entry("argv", argv)?,
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for ProgramArgItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Value::deserialize(deserializer)? {
            Value::String(value) => value
                .parse::<InterpolatedString>()
                .map(ProgramArgItem::from)
                .map_err(serde::de::Error::custom),
            Value::Object(map) => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct ProgramArgItemFields {
                    #[serde(default)]
                    when: Option<WhenPath>,
                    #[serde(default)]
                    each: Option<EachPath>,
                    #[serde(default)]
                    arg: Option<InterpolatedString>,
                    #[serde(default)]
                    argv: Option<ProgramArgList>,
                    #[serde(default)]
                    join: Option<String>,
                }

                let fields = serde_json::from_value::<ProgramArgItemFields>(Value::Object(map))
                    .map_err(serde::de::Error::custom)?;
                let value = match (fields.arg, fields.argv) {
                    (Some(arg), None) => ProgramArgValue::Arg(arg),
                    (None, Some(argv)) => ProgramArgValue::Argv(argv),
                    (Some(_), Some(_)) => {
                        return Err(serde::de::Error::custom(
                            "expected exactly one of `arg` or `argv`",
                        ));
                    }
                    (None, None) => {
                        return Err(serde::de::Error::custom(
                            "expected an object with one of `arg` or `argv`",
                        ));
                    }
                };
                let item = Self {
                    when: fields.when,
                    each: fields.each,
                    value,
                    join: fields.join,
                };
                item.validate().map_err(serde::de::Error::custom)?;
                Ok(item)
            }
            _ => Err(serde::de::Error::custom(
                "expected a string or an object with one of `arg` or `argv`",
            )),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ProgramEntrypoint(pub Vec<ProgramArgItem>);

impl ProgramEntrypoint {
    pub fn visit_args(&self, mut visit: impl FnMut(&InterpolatedString)) {
        for item in &self.0 {
            item.visit_values(&mut visit);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Visit slot names referenced anywhere in the command. Returns `true` if the command
    /// references all slots.
    pub fn visit_slot_uses(&self, mut visit: impl FnMut(&str)) -> bool {
        for item in &self.0 {
            if item.visit_slot_uses(&mut visit) {
                return true;
            }
        }
        false
    }
}

impl<'de> Deserialize<'de> for ProgramEntrypoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProgramEntrypointVisitor;

        impl<'de> Visitor<'de> for ProgramEntrypointVisitor {
            type Value = ProgramEntrypoint;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a shell-style string or an array of arguments")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                parse_program_arg_list(value)
                    .map(|args| {
                        ProgramEntrypoint(args.into_iter().map(ProgramArgItem::from).collect())
                    })
                    .map_err(E::custom)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&value)
            }

            fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                Vec::<ProgramArgItem>::deserialize(SeqAccessDeserializer::new(seq))
                    .map(ProgramEntrypoint)
            }
        }

        deserializer.deserialize_any(ProgramEntrypointVisitor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProgramEnvValue {
    pub when: Option<WhenPath>,
    pub each: Option<EachPath>,
    pub value: InterpolatedString,
    pub join: Option<String>,
}

impl ProgramEnvValue {
    pub fn value(&self) -> &InterpolatedString {
        &self.value
    }

    pub fn when(&self) -> Option<&WhenPath> {
        self.when.as_ref()
    }

    pub fn each(&self) -> Option<&EachPath> {
        self.each.as_ref()
    }

    pub fn is_repeated(&self) -> bool {
        self.each.is_some()
    }

    pub fn join(&self) -> Option<&str> {
        self.join.as_deref()
    }

    pub fn visit_values(&self, mut visit: impl FnMut(&InterpolatedString)) {
        visit(self.value());
    }

    /// Visit slot names referenced by this env value, including `when` conditions and repeated
    /// `each` selectors. Returns `true` if the value references all slots.
    pub fn visit_slot_uses(&self, mut visit: impl FnMut(&str)) -> bool {
        if let Some(when) = self.when()
            && visit_when_slot_uses(when, &mut visit)
        {
            return true;
        }

        if let Some(each) = self.each()
            && each.source() == InterpolationSource::Slots
            && let Some(slot) = each.slot()
        {
            visit(slot);
        }

        self.value().visit_slot_uses(visit)
    }

    fn validate(&self) -> Result<(), String> {
        match (self.each.as_ref(), self.join.as_ref()) {
            (None, Some(_)) => Err("`join` is only valid with `each`".to_string()),
            (Some(_), None) => Err("`join` is required with `each` in program.env".to_string()),
            _ => Ok(()),
        }
    }
}

fn visit_program_arg_list_slot_uses(args: &ProgramArgList, visit: &mut impl FnMut(&str)) -> bool {
    for arg in &args.0 {
        if arg.visit_slot_uses(&mut *visit) {
            return true;
        }
    }
    false
}

fn visit_when_slot_uses(when: &WhenPath, visit: &mut impl FnMut(&str)) -> bool {
    if when.source() != InterpolationSource::Slots {
        return false;
    }

    match parse_slot_query(when.query()) {
        Ok(parsed) => match parsed.target {
            SlotTarget::All => true,
            SlotTarget::Slot(slot) => {
                visit(slot);
                false
            }
        },
        Err(_) => when.query().is_empty(),
    }
}

impl From<InterpolatedString> for ProgramEnvValue {
    fn from(value: InterpolatedString) -> Self {
        Self {
            when: None,
            each: None,
            value,
            join: None,
        }
    }
}

impl Serialize for ProgramEnvValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.when.is_none() && self.each.is_none() && self.join.is_none() {
            return self.value.serialize(serializer);
        }

        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(None)?;
        if let Some(when) = &self.when {
            map.serialize_entry("when", when)?;
        }
        if let Some(each) = &self.each {
            map.serialize_entry("each", each)?;
        }
        if let Some(join) = &self.join {
            map.serialize_entry("join", join)?;
        }
        map.serialize_entry("value", &self.value)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for ProgramEnvValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Value::deserialize(deserializer)? {
            Value::String(value) => value
                .parse::<InterpolatedString>()
                .map(ProgramEnvValue::from)
                .map_err(serde::de::Error::custom),
            Value::Object(map) => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct ProgramEnvValueFields {
                    #[serde(default)]
                    when: Option<WhenPath>,
                    #[serde(default)]
                    each: Option<EachPath>,
                    value: InterpolatedString,
                    #[serde(default)]
                    join: Option<String>,
                }

                let value = serde_json::from_value::<ProgramEnvValueFields>(Value::Object(map))
                    .map_err(serde::de::Error::custom)?;
                let env_value = Self {
                    when: value.when,
                    each: value.each,
                    value: value.value,
                    join: value.join,
                };
                env_value.validate().map_err(serde::de::Error::custom)?;
                Ok(env_value)
            }
            _ => Err(serde::de::Error::custom(
                "expected an interpolation string or an object with `value`",
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(untagged)]
pub enum RawProgramArgList {
    ShellWords(InlineStringSpec),
    List(Vec<InlineStringSpec>),
}

impl<'de> Deserialize<'de> for RawProgramArgList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawProgramArgListVisitor;

        impl<'de> Visitor<'de> for RawProgramArgListVisitor {
            type Value = RawProgramArgList;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "a shell-style string, a `{ file: ... }` reference, or an array of strings",
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                parse_program_arg_list(value).map_err(E::custom)?;
                Ok(RawProgramArgList::ShellWords(InlineStringSpec::Inline(
                    value.to_string(),
                )))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&value)
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                deserialize_inline_string_spec_from_value(Value::deserialize(
                    MapAccessDeserializer::new(map),
                )?)
                .map(RawProgramArgList::ShellWords)
                .map_err(serde::de::Error::custom)
            }

            fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                Vec::<InlineStringSpec>::deserialize(SeqAccessDeserializer::new(seq))
                    .map(RawProgramArgList::List)
            }
        }

        deserializer.deserialize_any(RawProgramArgListVisitor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RawProgramArgValue {
    Arg(InlineStringSpec),
    Argv(RawProgramArgList),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawProgramArgItem {
    pub when: Option<WhenPath>,
    pub each: Option<EachPath>,
    pub value: RawProgramArgValue,
    pub join: Option<String>,
}

impl<'de> Deserialize<'de> for RawProgramArgItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Value::deserialize(deserializer)? {
            Value::String(value) => {
                value
                    .parse::<InterpolatedString>()
                    .map_err(serde::de::Error::custom)?;
                Ok(Self {
                    when: None,
                    each: None,
                    value: RawProgramArgValue::Arg(InlineStringSpec::Inline(value)),
                    join: None,
                })
            }
            Value::Object(map) => {
                let value = Value::Object(map.clone());
                if map.contains_key("file") {
                    deserialize_inline_string_spec_from_value(value)
                        .map(|arg| Self {
                            when: None,
                            each: None,
                            value: RawProgramArgValue::Arg(arg),
                            join: None,
                        })
                        .map_err(serde::de::Error::custom)
                } else {
                    #[derive(Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct RawProgramArgItemFields {
                        #[serde(default)]
                        when: Option<WhenPath>,
                        #[serde(default)]
                        each: Option<EachPath>,
                        #[serde(default)]
                        arg: Option<InlineStringSpec>,
                        #[serde(default)]
                        argv: Option<RawProgramArgList>,
                        #[serde(default)]
                        join: Option<String>,
                    }

                    let value =
                        serde_json::from_value::<RawProgramArgItemFields>(Value::Object(map))
                            .map_err(serde::de::Error::custom)?;
                    let item_value = match (value.arg, value.argv) {
                        (Some(arg), None) => RawProgramArgValue::Arg(arg),
                        (None, Some(argv)) => RawProgramArgValue::Argv(argv),
                        (Some(_), Some(_)) => {
                            return Err(serde::de::Error::custom(
                                "expected exactly one of `arg` or `argv`",
                            ));
                        }
                        (None, None) => {
                            return Err(serde::de::Error::custom(
                                "expected an object with one of `arg` or `argv`",
                            ));
                        }
                    };
                    let item = Self {
                        when: value.when,
                        each: value.each,
                        value: item_value,
                        join: value.join,
                    };
                    item.validate().map_err(serde::de::Error::custom)?;
                    Ok(item)
                }
            }
            _ => Err(serde::de::Error::custom(
                "expected a string, a `{ file: ... }` reference, or an object with one of `arg` \
                 or `argv`",
            )),
        }
    }
}

impl RawProgramArgItem {
    fn validate(&self) -> Result<(), String> {
        match (self.each.as_ref(), &self.value, self.join.as_ref()) {
            (None, _, Some(_)) => Err("`join` is only valid with `each` and `arg`".to_string()),
            (Some(_), RawProgramArgValue::Argv(_), Some(_)) => {
                Err("`join` is only valid with `each` and `arg`".to_string())
            }
            _ => Ok(()),
        }
    }
}

impl Serialize for RawProgramArgItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.when.is_none()
            && self.each.is_none()
            && self.join.is_none()
            && let RawProgramArgValue::Arg(arg) = &self.value
        {
            return arg.serialize(serializer);
        }

        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(None)?;
        if let Some(when) = &self.when {
            map.serialize_entry("when", when)?;
        }
        if let Some(each) = &self.each {
            map.serialize_entry("each", each)?;
        }
        if let Some(join) = &self.join {
            map.serialize_entry("join", join)?;
        }
        match &self.value {
            RawProgramArgValue::Arg(arg) => map.serialize_entry("arg", arg)?,
            RawProgramArgValue::Argv(argv) => map.serialize_entry("argv", argv)?,
        }
        map.end()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(untagged)]
pub enum RawProgramEntrypoint {
    ShellWords(InlineStringSpec),
    Items(Vec<RawProgramArgItem>),
}

impl Default for RawProgramEntrypoint {
    fn default() -> Self {
        Self::Items(Vec::new())
    }
}

impl<'de> Deserialize<'de> for RawProgramEntrypoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawProgramEntrypointVisitor;

        impl<'de> Visitor<'de> for RawProgramEntrypointVisitor {
            type Value = RawProgramEntrypoint;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "a shell-style string, a `{ file: ... }` reference, or an array of arguments",
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                parse_program_arg_list(value).map_err(E::custom)?;
                Ok(RawProgramEntrypoint::ShellWords(InlineStringSpec::Inline(
                    value.to_string(),
                )))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&value)
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                deserialize_inline_string_spec_from_value(Value::deserialize(
                    MapAccessDeserializer::new(map),
                )?)
                .map(RawProgramEntrypoint::ShellWords)
                .map_err(serde::de::Error::custom)
            }

            fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                Vec::<RawProgramArgItem>::deserialize(SeqAccessDeserializer::new(seq))
                    .map(RawProgramEntrypoint::Items)
            }
        }

        deserializer.deserialize_any(RawProgramEntrypointVisitor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawProgramEnvValue {
    pub when: Option<WhenPath>,
    pub each: Option<EachPath>,
    pub value: InlineStringSpec,
    pub join: Option<String>,
}

impl<'de> Deserialize<'de> for RawProgramEnvValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Value::deserialize(deserializer)? {
            Value::String(value) => {
                value
                    .parse::<InterpolatedString>()
                    .map_err(serde::de::Error::custom)?;
                Ok(Self {
                    when: None,
                    each: None,
                    value: InlineStringSpec::Inline(value),
                    join: None,
                })
            }
            Value::Object(map) => {
                let value = Value::Object(map.clone());
                if map.contains_key("file") {
                    deserialize_inline_string_spec_from_value(value)
                        .map(|value| Self {
                            when: None,
                            each: None,
                            value,
                            join: None,
                        })
                        .map_err(serde::de::Error::custom)
                } else {
                    #[derive(Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct RawProgramEnvValueFields {
                        #[serde(default)]
                        when: Option<WhenPath>,
                        #[serde(default)]
                        each: Option<EachPath>,
                        value: InlineStringSpec,
                        #[serde(default)]
                        join: Option<String>,
                    }

                    let value =
                        serde_json::from_value::<RawProgramEnvValueFields>(Value::Object(map))
                            .map_err(serde::de::Error::custom)?;
                    let env_value = Self {
                        when: value.when,
                        each: value.each,
                        value: value.value,
                        join: value.join,
                    };
                    env_value.validate().map_err(serde::de::Error::custom)?;
                    Ok(env_value)
                }
            }
            _ => Err(serde::de::Error::custom(
                "expected an interpolation string, a `{ file: ... }` reference, or an object with \
                 `value`",
            )),
        }
    }
}

impl RawProgramEnvValue {
    fn validate(&self) -> Result<(), String> {
        match (self.each.as_ref(), self.join.as_ref()) {
            (None, Some(_)) => Err("`join` is only valid with `each`".to_string()),
            (Some(_), None) => Err("`join` is required with `each` in program.env".to_string()),
            _ => Ok(()),
        }
    }
}

impl Serialize for RawProgramEnvValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.when.is_none() && self.each.is_none() && self.join.is_none() {
            return self.value.serialize(serializer);
        }

        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(None)?;
        if let Some(when) = &self.when {
            map.serialize_entry("when", when)?;
        }
        if let Some(each) = &self.each {
            map.serialize_entry("each", each)?;
        }
        if let Some(join) = &self.join {
            map.serialize_entry("join", join)?;
        }
        map.serialize_entry("value", &self.value)?;
        map.end()
    }
}

impl RawProgramArgList {
    pub fn resolve(
        self,
        pointer: &str,
        resolve_string: &mut impl FnMut(InlineStringSpec, &str) -> Result<String, Error>,
    ) -> Result<ProgramArgList, Error> {
        match self {
            Self::ShellWords(spec) => {
                let raw = resolve_string(spec, pointer)?;
                parse_program_arg_list(&raw).map(Self::resolved_args_to_list)
            }
            Self::List(values) => values
                .into_iter()
                .enumerate()
                .map(|(idx, value)| {
                    let raw = resolve_string(value, &pointer_with_index(pointer, idx))?;
                    raw.parse::<InterpolatedString>()
                })
                .collect::<Result<Vec<_>, _>>()
                .map(ProgramArgList),
        }
    }

    fn resolved_args_to_list(args: Vec<InterpolatedString>) -> ProgramArgList {
        ProgramArgList(args)
    }
}

impl From<ProgramArgList> for RawProgramArgList {
    fn from(value: ProgramArgList) -> Self {
        Self::List(value.0.into_iter().map(InlineStringSpec::from).collect())
    }
}

impl RawProgramArgItem {
    pub fn resolve(
        self,
        pointer: &str,
        resolve_string: &mut impl FnMut(InlineStringSpec, &str) -> Result<String, Error>,
    ) -> Result<ProgramArgItem, Error> {
        let value = match self.value {
            RawProgramArgValue::Arg(value) => {
                let raw = resolve_string(value, &pointer_with_segment(pointer, "arg"))?;
                ProgramArgValue::Arg(raw.parse::<InterpolatedString>()?)
            }
            RawProgramArgValue::Argv(argv) => ProgramArgValue::Argv(
                argv.resolve(&pointer_with_segment(pointer, "argv"), resolve_string)?,
            ),
        };
        Ok(ProgramArgItem {
            when: self.when,
            each: self.each,
            value,
            join: self.join,
        })
    }
}

impl From<ProgramArgItem> for RawProgramArgItem {
    fn from(value: ProgramArgItem) -> Self {
        let raw_value = match value.value {
            ProgramArgValue::Arg(arg) => RawProgramArgValue::Arg(arg.into()),
            ProgramArgValue::Argv(argv) => RawProgramArgValue::Argv(argv.into()),
        };
        Self {
            when: value.when,
            each: value.each,
            value: raw_value,
            join: value.join,
        }
    }
}

impl RawProgramEntrypoint {
    pub fn resolve(
        self,
        pointer: &str,
        resolve_string: &mut impl FnMut(InlineStringSpec, &str) -> Result<String, Error>,
    ) -> Result<ProgramEntrypoint, Error> {
        match self {
            Self::ShellWords(spec) => {
                let raw = resolve_string(spec, pointer)?;
                parse_program_arg_list(&raw).map(|args| {
                    ProgramEntrypoint(args.into_iter().map(ProgramArgItem::from).collect())
                })
            }
            Self::Items(items) => items
                .into_iter()
                .enumerate()
                .map(|(idx, item)| item.resolve(&pointer_with_index(pointer, idx), resolve_string))
                .collect::<Result<Vec<_>, _>>()
                .map(ProgramEntrypoint),
        }
    }
}

impl From<ProgramEntrypoint> for RawProgramEntrypoint {
    fn from(value: ProgramEntrypoint) -> Self {
        Self::Items(value.0.into_iter().map(RawProgramArgItem::from).collect())
    }
}

impl RawProgramEnvValue {
    pub fn resolve(
        self,
        pointer: &str,
        resolve_string: &mut impl FnMut(InlineStringSpec, &str) -> Result<String, Error>,
    ) -> Result<ProgramEnvValue, Error> {
        let raw = resolve_string(self.value, &pointer_with_segment(pointer, "value"))?;
        Ok(ProgramEnvValue {
            when: self.when,
            each: self.each,
            value: raw.parse::<InterpolatedString>()?,
            join: self.join,
        })
    }
}

impl From<ProgramEnvValue> for RawProgramEnvValue {
    fn from(value: ProgramEnvValue) -> Self {
        Self {
            when: value.when,
            each: value.each,
            value: value.value.into(),
            join: value.join,
        }
    }
}

fn deserialize_program_arg_list<'de, D>(
    deserializer: D,
) -> Result<Vec<InterpolatedString>, D::Error>
where
    D: Deserializer<'de>,
{
    struct ProgramArgListVisitor;

    impl<'de> Visitor<'de> for ProgramArgListVisitor {
        type Value = Vec<InterpolatedString>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a shell-style string or an array of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            parse_program_arg_list(value).map_err(E::custom)
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            self.visit_str(&value)
        }

        fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            Vec::<InterpolatedString>::deserialize(SeqAccessDeserializer::new(seq))
        }
    }

    deserializer.deserialize_any(ProgramArgListVisitor)
}

fn parse_program_arg_list(input: &str) -> Result<Vec<InterpolatedString>, Error> {
    let tokens = shlex::split(input).ok_or(Error::UnclosedQuote)?;
    tokens
        .into_iter()
        .map(|token| token.parse::<InterpolatedString>())
        .collect()
}

fn deserialize_inline_string_spec_from_value(value: Value) -> Result<InlineStringSpec, String> {
    match value {
        Value::String(value) => Ok(InlineStringSpec::Inline(value)),
        Value::Object(map) => serde_json::from_value::<FileRefSpec>(Value::Object(map))
            .map(InlineStringSpec::File)
            .map_err(|err| err.to_string()),
        _ => Err("expected a string or a `{ file: ... }` reference".to_string()),
    }
}

fn parse_pointer(pointer: &str) -> PointerBuf {
    if pointer.is_empty() {
        PointerBuf::new()
    } else {
        PointerBuf::parse(pointer.to_string()).expect("pointer must be valid")
    }
}

fn pointer_with_segment(pointer: &str, segment: impl AsRef<str>) -> String {
    let mut pointer = parse_pointer(pointer);
    pointer.push_back(segment.as_ref());
    pointer.to_string()
}

fn pointer_with_index(pointer: &str, index: usize) -> String {
    pointer_with_segment(pointer, index.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpolation_parsing_splits_parts() {
        let parsed: InterpolatedString = "a ${config.b} c".parse().unwrap();
        assert_eq!(
            parsed.parts,
            vec![
                InterpolatedPart::Literal("a ".to_string()),
                InterpolatedPart::Interpolation {
                    source: InterpolationSource::Config,
                    query: "b".to_string()
                },
                InterpolatedPart::Literal(" c".to_string()),
            ]
        );
    }

    #[test]
    fn interpolation_without_placeholders_is_literal() {
        let parsed: InterpolatedString = "hello".parse().unwrap();
        assert_eq!(
            parsed.parts,
            vec![InterpolatedPart::Literal("hello".to_string())]
        );
    }

    #[test]
    fn interpolation_multiple_and_adjacent() {
        let parsed: InterpolatedString = "${config.a}${slots.llm.url}".parse().unwrap();
        assert_eq!(
            parsed.parts,
            vec![
                InterpolatedPart::Interpolation {
                    source: InterpolationSource::Config,
                    query: "a".to_string()
                },
                InterpolatedPart::Interpolation {
                    source: InterpolationSource::Slots,
                    query: "llm.url".to_string()
                },
            ]
        );
    }

    #[test]
    fn interpolation_unknown_source_errors() {
        assert!("${foo.bar}".parse::<InterpolatedString>().is_err());
    }

    #[test]
    fn interpolation_missing_closing_brace_errors() {
        assert!("x ${config.a".parse::<InterpolatedString>().is_err());
    }

    #[test]
    fn when_path_requires_config_path_or_slot_path() {
        let config = "config.value".parse::<WhenPath>().unwrap();
        assert_eq!(config.source(), InterpolationSource::Config);
        assert_eq!(config.query(), "value");

        let slot = "slots.backend".parse::<WhenPath>().unwrap();
        assert_eq!(slot.source(), InterpolationSource::Slots);
        assert_eq!(slot.query(), "backend");

        let slot_field = "slots.backend.url".parse::<WhenPath>().unwrap();
        assert_eq!(slot_field.source(), InterpolationSource::Slots);
        assert_eq!(slot_field.query(), "backend.url");

        assert!("config".parse::<WhenPath>().is_err());
        assert!("slots".parse::<WhenPath>().is_err());
        assert!("slots.backend..url".parse::<WhenPath>().is_err());
        assert!("foo.route.url".parse::<WhenPath>().is_err());
    }

    #[test]
    fn program_entrypoint_string_sugar_yields_plain_args() {
        let parsed: ProgramEntrypoint =
            serde_json::from_str("\"python3 -m http.server 8080\"").unwrap();
        assert_eq!(parsed.0.len(), 4);
        assert_eq!(parsed.0[0].arg().unwrap().to_string(), "python3");
        assert_eq!(parsed.0[1].arg().unwrap().to_string(), "-m");
        assert_eq!(parsed.0[2].arg().unwrap().to_string(), "http.server");
        assert_eq!(parsed.0[3].arg().unwrap().to_string(), "8080");
    }

    #[test]
    fn conditional_program_arg_item_supports_nested_shlex_sugar() {
        let parsed: ProgramEntrypoint = serde_json::from_str(
            r#"[
              "server",
              {
                "when": "config.profile",
                "argv": "--profile ${config.profile}"
              }
            ]"#,
        )
        .unwrap();
        let item = &parsed.0[1];
        let when = item.when().expect("expected conditional item");
        let argv = item.argv().expect("expected argv item");
        assert_eq!(when.source(), InterpolationSource::Config);
        assert_eq!(when.query(), "profile");
        assert_eq!(argv.0.len(), 2);
        assert_eq!(argv.0[0].to_string(), "--profile");
        assert_eq!(argv.0[1].to_string(), "${config.profile}");
    }
}
