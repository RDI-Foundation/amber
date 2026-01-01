#![forbid(unsafe_code)]

mod diagnostic;
pub mod spans;

pub use diagnostic::{DiagnosticError, DiagnosticKind, parse};
pub use json5::{
    Deserializer, Error, ErrorCode, Position, Serializer, from_str, to_string, to_writer,
};
