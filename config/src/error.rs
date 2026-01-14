use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Msg(String),
    Schema(String),
    Validation(String),
    Interp(String),
}

impl ConfigError {
    pub fn msg(message: impl Into<String>) -> Self {
        Self::Msg(message.into())
    }

    pub fn schema(message: impl Into<String>) -> Self {
        Self::Schema(message.into())
    }

    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }

    pub fn interp(message: impl Into<String>) -> Self {
        Self::Interp(message.into())
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Msg(message)
            | Self::Schema(message)
            | Self::Validation(message)
            | Self::Interp(message) => message.as_str(),
        }
    }

    pub fn into_message(self) -> String {
        match self {
            Self::Msg(message)
            | Self::Schema(message)
            | Self::Validation(message)
            | Self::Interp(message) => message,
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for ConfigError {}

pub type Result<T> = std::result::Result<T, ConfigError>;
