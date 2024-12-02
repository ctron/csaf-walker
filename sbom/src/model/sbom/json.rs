use serde::Deserialize;
use serde_json::Value;

pub enum JsonPayload<'a> {
    Value(Value),
    Bytes(&'a [u8]),
}

impl JsonPayload<'_> {
    pub fn parse<T>(self) -> Result<T, serde_json::Error>
    where
        for<'de> T: Deserialize<'de>,
    {
        match self {
            Self::Value(data) => serde_json::from_value(data),
            Self::Bytes(data) => serde_json::from_slice(data),
        }
    }
}

impl From<Value> for JsonPayload<'static> {
    fn from(value: Value) -> Self {
        Self::Value(value)
    }
}

impl<'a> From<&'a [u8]> for JsonPayload<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self::Bytes(value)
    }
}
impl<'a, const N: usize> From<&'a [u8; N]> for JsonPayload<'a> {
    fn from(value: &'a [u8; N]) -> Self {
        Self::Bytes(value)
    }
}
