use std::{borrow::Borrow, fmt, sync::Arc};

use crate::error::Error;

pub(crate) fn ensure_name_no_dot(name: &str, kind: &'static str) -> Result<(), Error> {
    if name.contains('.') {
        return Err(Error::InvalidName {
            kind,
            name: name.to_string(),
        });
    }
    Ok(())
}

macro_rules! name_type {
    ($name:ident, $kind:expr) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Arc<str>);

        impl $name {
            pub fn new(name: String) -> Result<Self, Error> {
                crate::names::ensure_name_no_dot(&name, $kind)?;
                Ok(Self(Arc::from(name)))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = Error;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = Error;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                crate::names::ensure_name_no_dot(value, $kind)?;
                Ok(Self(Arc::from(value)))
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0.to_string()
            }
        }

        impl From<&$name> for String {
            fn from(value: &$name) -> Self {
                value.0.to_string()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }
    };
}

name_type!(ChildName, "child");
name_type!(SlotName, "slot");
name_type!(ProvideName, "provide");
name_type!(ExportName, "export");
name_type!(BindingName, "binding");
name_type!(FrameworkCapabilityName, "framework capability");
