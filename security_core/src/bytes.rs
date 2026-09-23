//! `Base64Bytes`：以 URL-safe Base64 序列化字节的新类型，用于 JSON 中存放 salt/nonce/密文。
//!
//! 采用 `URL_SAFE_NO_PAD` 编码，保证 JSON 紧凑且不依赖系统字符集。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// 在 JSON 中渲染为 Base64 字符串的字节序列。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Base64Bytes(pub Vec<u8>);

impl From<Vec<u8>> for Base64Bytes {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<&[u8]> for Base64Bytes {
    fn from(v: &[u8]) -> Self {
        Self(v.to_vec())
    }
}

impl AsRef<[u8]> for Base64Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for Base64Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Base64Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)?;
        Ok(Self(bytes))
    }
}
