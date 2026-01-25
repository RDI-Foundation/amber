use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize};
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

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ProgramArgs(pub Vec<InterpolatedString>);

impl<'de> Deserialize<'de> for ProgramArgs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum ProgramArgsForm {
            String(String),
            List(Vec<InterpolatedString>),
        }

        match ProgramArgsForm::deserialize(deserializer)? {
            ProgramArgsForm::String(s) => {
                let tokens = shlex::split(&s)
                    .ok_or_else(|| serde::de::Error::custom(Error::UnclosedQuote))?;
                let mut args = Vec::new();
                for token in tokens {
                    args.push(
                        token
                            .parse::<InterpolatedString>()
                            .map_err(serde::de::Error::custom)?,
                    );
                }
                Ok(ProgramArgs(args))
            }
            ProgramArgsForm::List(list) => Ok(ProgramArgs(list)),
        }
    }
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
}
