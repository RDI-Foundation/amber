#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ImageRef {
    pub name: &'static str,
    pub tag: &'static str,
    pub registry: &'static str,
    pub reference: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/images.rs"));
