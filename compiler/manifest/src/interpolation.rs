use std::{fmt, str::FromStr};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{SeqAccess, Visitor, value::SeqAccessDeserializer},
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
    slot: String,
}

impl EachPath {
    pub fn slot(&self) -> &str {
        &self.slot
    }
}

impl fmt::Display for EachPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "slots.{}", self.slot)
    }
}

impl FromStr for EachPath {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let Some(slot) = input.strip_prefix("slots.") else {
            return Err(Error::InvalidEachPath {
                input: input.to_string(),
                message: "expected `slots.<slot>`".to_string(),
            });
        };
        if slot.is_empty() || slot.contains('.') {
            return Err(Error::InvalidEachPath {
                input: input.to_string(),
                message: "expected `slots.<slot>`".to_string(),
            });
        }

        Ok(Self {
            slot: slot.to_string(),
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramArgGroup {
    pub when: WhenPath,
    pub argv: ProgramArgList,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepeatedProgramArgv {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<WhenPath>,
    pub each: EachPath,
    pub argv: ProgramArgList,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepeatedProgramArg {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<WhenPath>,
    pub each: EachPath,
    pub arg: InterpolatedString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join: Option<String>,
}

impl ProgramArgGroup {
    pub fn visit_values(&self, mut visit: impl FnMut(&InterpolatedString)) {
        for arg in &self.argv.0 {
            visit(arg);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProgramArgItem {
    Arg(InterpolatedString),
    Group(ProgramArgGroup),
    RepeatedArgv(RepeatedProgramArgv),
    RepeatedArg(RepeatedProgramArg),
}

impl ProgramArgItem {
    pub fn arg(&self) -> Option<&InterpolatedString> {
        match self {
            Self::Arg(arg) => Some(arg),
            Self::Group(_) | Self::RepeatedArgv(_) | Self::RepeatedArg(_) => None,
        }
    }

    pub fn group(&self) -> Option<&ProgramArgGroup> {
        match self {
            Self::Arg(_) => None,
            Self::Group(group) => Some(group),
            Self::RepeatedArgv(_) | Self::RepeatedArg(_) => None,
        }
    }

    pub fn repeated_argv(&self) -> Option<&RepeatedProgramArgv> {
        match self {
            Self::RepeatedArgv(repeated) => Some(repeated),
            Self::Arg(_) | Self::Group(_) | Self::RepeatedArg(_) => None,
        }
    }

    pub fn repeated_arg(&self) -> Option<&RepeatedProgramArg> {
        match self {
            Self::RepeatedArg(repeated) => Some(repeated),
            Self::Arg(_) | Self::Group(_) | Self::RepeatedArgv(_) => None,
        }
    }

    pub fn when(&self) -> Option<&WhenPath> {
        match self {
            Self::Arg(_) => None,
            Self::Group(group) => Some(&group.when),
            Self::RepeatedArgv(repeated) => repeated.when.as_ref(),
            Self::RepeatedArg(repeated) => repeated.when.as_ref(),
        }
    }

    pub fn visit_values(&self, mut visit: impl FnMut(&InterpolatedString)) {
        match self {
            Self::Arg(arg) => visit(arg),
            Self::Group(group) => group.visit_values(visit),
            Self::RepeatedArgv(repeated) => {
                for arg in &repeated.argv.0 {
                    visit(arg);
                }
            }
            Self::RepeatedArg(repeated) => visit(&repeated.arg),
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

        match self {
            Self::Arg(arg) => arg.visit_slot_uses(visit),
            Self::Group(group) => visit_program_arg_list_slot_uses(&group.argv, &mut visit),
            Self::RepeatedArgv(repeated) => {
                visit(repeated.each.slot());
                visit_program_arg_list_slot_uses(&repeated.argv, &mut visit)
            }
            Self::RepeatedArg(repeated) => {
                visit(repeated.each.slot());
                repeated.arg.visit_slot_uses(visit)
            }
        }
    }
}

impl From<InterpolatedString> for ProgramArgItem {
    fn from(value: InterpolatedString) -> Self {
        Self::Arg(value)
    }
}

impl Serialize for ProgramArgItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Arg(arg) => arg.serialize(serializer),
            Self::Group(group) => group.serialize(serializer),
            Self::RepeatedArgv(repeated) => repeated.serialize(serializer),
            Self::RepeatedArg(repeated) => repeated.serialize(serializer),
        }
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
                .map(ProgramArgItem::Arg)
                .map_err(serde::de::Error::custom),
            Value::Object(map) => {
                let value = Value::Object(map.clone());
                if map.contains_key("each") {
                    if map.contains_key("argv") {
                        serde_json::from_value::<RepeatedProgramArgv>(value)
                            .map(ProgramArgItem::RepeatedArgv)
                            .map_err(serde::de::Error::custom)
                    } else if map.contains_key("arg") {
                        serde_json::from_value::<RepeatedProgramArg>(value)
                            .map(ProgramArgItem::RepeatedArg)
                            .map_err(serde::de::Error::custom)
                    } else {
                        Err(serde::de::Error::custom(
                            "expected an object with `each` and one of `argv` or `arg`",
                        ))
                    }
                } else {
                    serde_json::from_value::<ProgramArgGroup>(value)
                        .map(ProgramArgItem::Group)
                        .map_err(serde::de::Error::custom)
                }
            }
            _ => Err(serde::de::Error::custom(
                "expected a string or an object with `when`/`argv` or `each`",
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

    pub fn groups(&self) -> impl Iterator<Item = &ProgramArgGroup> {
        self.0.iter().filter_map(ProgramArgItem::group)
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
                        ProgramEntrypoint(args.into_iter().map(ProgramArgItem::Arg).collect())
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramEnvGroup {
    pub when: WhenPath,
    pub value: InterpolatedString,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepeatedProgramEnv {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<WhenPath>,
    pub each: EachPath,
    pub value: InterpolatedString,
    pub join: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProgramEnvValue {
    Value(InterpolatedString),
    Group(ProgramEnvGroup),
    Repeated(RepeatedProgramEnv),
}

impl ProgramEnvValue {
    pub fn value(&self) -> &InterpolatedString {
        match self {
            Self::Value(value) => value,
            Self::Group(group) => &group.value,
            Self::Repeated(repeated) => &repeated.value,
        }
    }

    pub fn group(&self) -> Option<&ProgramEnvGroup> {
        match self {
            Self::Value(_) => None,
            Self::Group(group) => Some(group),
            Self::Repeated(_) => None,
        }
    }

    pub fn repeated(&self) -> Option<&RepeatedProgramEnv> {
        match self {
            Self::Repeated(repeated) => Some(repeated),
            Self::Value(_) | Self::Group(_) => None,
        }
    }

    pub fn when(&self) -> Option<&WhenPath> {
        match self {
            Self::Value(_) => None,
            Self::Group(group) => Some(&group.when),
            Self::Repeated(repeated) => repeated.when.as_ref(),
        }
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

        if let Some(repeated) = self.repeated() {
            visit(repeated.each.slot());
        }

        self.value().visit_slot_uses(visit)
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
        Self::Value(value)
    }
}

impl Serialize for ProgramEnvValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Value(value) => value.serialize(serializer),
            Self::Group(group) => group.serialize(serializer),
            Self::Repeated(repeated) => repeated.serialize(serializer),
        }
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
                .map(ProgramEnvValue::Value)
                .map_err(serde::de::Error::custom),
            Value::Object(map) => {
                let value = Value::Object(map.clone());
                if map.contains_key("each") {
                    serde_json::from_value::<RepeatedProgramEnv>(value)
                        .map(ProgramEnvValue::Repeated)
                        .map_err(serde::de::Error::custom)
                } else {
                    serde_json::from_value::<ProgramEnvGroup>(value)
                        .map(ProgramEnvValue::Group)
                        .map_err(serde::de::Error::custom)
                }
            }
            _ => Err(serde::de::Error::custom(
                "expected an interpolation string or an object with `when`/`value` or `each`",
            )),
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
    fn conditional_program_arg_group_supports_nested_shlex_sugar() {
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
        let group = parsed.0[1].group().expect("expected conditional group");
        assert_eq!(group.when.source(), InterpolationSource::Config);
        assert_eq!(group.when.query(), "profile");
        assert_eq!(group.argv.0.len(), 2);
        assert_eq!(group.argv.0[0].to_string(), "--profile");
        assert_eq!(group.argv.0[1].to_string(), "${config.profile}");
    }
}
