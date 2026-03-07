use std::{fmt, str::FromStr};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{
        SeqAccess, Visitor,
        value::{MapAccessDeserializer, SeqAccessDeserializer},
    },
};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::Error;

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
            "bindings" => InterpolationSource::Bindings,
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
    Bindings,
}

impl fmt::Display for InterpolationSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            InterpolationSource::Config => "config",
            InterpolationSource::Slots => "slots",
            InterpolationSource::Bindings => "bindings",
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
pub struct ConditionalInterpolationPath {
    source: InterpolationSource,
    query: String,
}

impl ConditionalInterpolationPath {
    pub fn source(&self) -> InterpolationSource {
        self.source
    }

    pub fn query(&self) -> &str {
        &self.query
    }
}

impl fmt::Display for ConditionalInterpolationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.source)?;
        if !self.query.is_empty() {
            write!(f, ".{}", self.query)?;
        }
        Ok(())
    }
}

impl FromStr for ConditionalInterpolationPath {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let InterpolatedPart::Interpolation { source, query } = input.parse()? else {
            unreachable!("conditional interpolation path parser never returns literals");
        };
        if !matches!(
            source,
            InterpolationSource::Config | InterpolationSource::Slots
        ) {
            return Err(Error::InvalidConditionalInterpolationPath(
                input.to_string(),
            ));
        }
        Ok(Self { source, query })
    }
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
    pub when_present: ConditionalInterpolationPath,
    pub argv: ProgramArgList,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProgramArgItem {
    Arg(InterpolatedString),
    Group(ProgramArgGroup),
}

impl ProgramArgItem {
    pub fn arg(&self) -> Option<&InterpolatedString> {
        match self {
            Self::Arg(arg) => Some(arg),
            Self::Group(_) => None,
        }
    }

    pub fn group(&self) -> Option<&ProgramArgGroup> {
        match self {
            Self::Arg(_) => None,
            Self::Group(group) => Some(group),
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
        }
    }
}

impl<'de> Deserialize<'de> for ProgramArgItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProgramArgItemVisitor;

        impl<'de> Visitor<'de> for ProgramArgItemVisitor {
            type Value = ProgramArgItem;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a program arg string or a conditional argv group")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value
                    .parse::<InterpolatedString>()
                    .map(ProgramArgItem::Arg)
                    .map_err(E::custom)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&value)
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                ProgramArgGroup::deserialize(MapAccessDeserializer::new(map))
                    .map(ProgramArgItem::Group)
            }
        }

        deserializer.deserialize_any(ProgramArgItemVisitor)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ProgramEntrypoint(pub Vec<ProgramArgItem>);

impl ProgramEntrypoint {
    pub fn visit_args(&self, mut visit: impl FnMut(&InterpolatedString)) {
        for item in &self.0 {
            match item {
                ProgramArgItem::Arg(arg) => visit(arg),
                ProgramArgItem::Group(group) => {
                    for arg in &group.argv.0 {
                        visit(arg);
                    }
                }
            }
        }
    }

    pub fn groups(&self) -> impl Iterator<Item = &ProgramArgGroup> {
        self.0.iter().filter_map(ProgramArgItem::group)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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
                f.write_str("a shell-style string or an array of program args")
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
            f.write_str("a shell-style string or an array of interpolated strings")
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
    fn interpolation_parsing_supports_bindings() {
        let parsed: InterpolatedString = "${bindings.route.url}".parse().unwrap();
        assert_eq!(
            parsed.parts,
            vec![InterpolatedPart::Interpolation {
                source: InterpolationSource::Bindings,
                query: "route.url".to_string()
            }]
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
    fn conditional_interpolation_path_requires_supported_prefix() {
        let config_root = "config".parse::<ConditionalInterpolationPath>().unwrap();
        assert_eq!(config_root.source(), InterpolationSource::Config);
        assert_eq!(config_root.query(), "");

        let config = "config.value"
            .parse::<ConditionalInterpolationPath>()
            .unwrap();
        assert_eq!(config.source(), InterpolationSource::Config);
        assert_eq!(config.query(), "value");

        let slots_root = "slots".parse::<ConditionalInterpolationPath>().unwrap();
        assert_eq!(slots_root.source(), InterpolationSource::Slots);
        assert_eq!(slots_root.query(), "");

        let slot = "slots.backend.url"
            .parse::<ConditionalInterpolationPath>()
            .unwrap();
        assert_eq!(slot.source(), InterpolationSource::Slots);
        assert_eq!(slot.query(), "backend.url");

        assert!(
            "bindings.route.url"
                .parse::<ConditionalInterpolationPath>()
                .is_err()
        );
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
                "when_present": "config.profile",
                "argv": "--profile ${config.profile}"
              }
            ]"#,
        )
        .unwrap();
        let group = parsed.0[1].group().expect("expected conditional group");
        assert_eq!(group.when_present.source(), InterpolationSource::Config);
        assert_eq!(group.when_present.query(), "profile");
        assert_eq!(group.argv.0.len(), 2);
        assert_eq!(group.argv.0[0].to_string(), "--profile");
        assert_eq!(group.argv.0[1].to_string(), "${config.profile}");
    }
}
