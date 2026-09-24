//! 字段级封装（sealing）：把单个字段明文加密为自描述二进制块。
//!
//! 格式：`version(1B) || nonce(12B) || ciphertext_with_tag`，用于数据库列级加密
//! （对应 docs/04 的 `secret_fields.ciphertext` 与 `accounts.*_enc`）。
//!
//! 与 `Wrap` 的区别：`Wrap` 用于包裹密钥（含 KDF 参数、JSON 序列化）；
//! `seal` 用于包裹数据字段（紧凑二进制、无 KDF 元数据）。

use crate::cipher;
use crate::error::SecurityError;

/// 当前 seal 格式版本。
pub const SEAL_VERSION: u8 = 1;

/// 将明文字节封装为 `version || nonce || ciphertext_with_tag`。
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, SecurityError> {
    let (nonce, ciphertext) = cipher::encrypt(key, plaintext)?;
    let mut out = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
    out.push(SEAL_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// 解开 `seal` 生成的封装块。
pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, SecurityError> {
    let (version, rest) = sealed
        .split_first()
        .ok_or(SecurityError::CiphertextTooShort)?;
    if *version != SEAL_VERSION {
        return Err(SecurityError::VersionMismatch {
            expected: u32::from(SEAL_VERSION),
            got: u32::from(*version),
        });
    }
    if rest.len() < cipher::NONCE_LEN {
        return Err(SecurityError::CiphertextTooShort);
    }
    let (nonce, ciphertext) = rest.split_at(cipher::NONCE_LEN);
    cipher::decrypt(key, nonce, ciphertext)
}

/// 封装可空字段：`None` → `None`，`Some` → 加密。
pub fn seal_opt(key: &[u8; 32], value: Option<&str>) -> Result<Option<Vec<u8>>, SecurityError> {
    value.map(|v| seal(key, v.as_bytes())).transpose()
}

/// 解开可空字段：`None` → `None`，`Some(bytes)` → 解密为字符串。
pub fn open_opt(key: &[u8; 32], sealed: Option<&[u8]>) -> Result<Option<String>, SecurityError> {
    sealed
        .map(|blob| {
            let bytes = open(key, blob)?;
            String::from_utf8(bytes).map_err(|_| SecurityError::Decryption)
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [5u8; 32]
    }

    #[test]
    fn seal_roundtrips() {
        let sealed = seal(&key(), b"hello field").unwrap();
        let opened = open(&key(), &sealed).unwrap();
        assert_eq!(opened, b"hello field");
    }

    #[test]
    fn sealed_blob_starts_with_version_byte() {
        let sealed = seal(&key(), b"x").unwrap();
        assert_eq!(sealed.first(), Some(&SEAL_VERSION));
    }

    #[test]
    fn sealed_blob_does_not_contain_plaintext() {
        let sealed = seal(&key(), b"TOPSECRET").unwrap();
        assert!(!sealed.windows(b"TOPSECRET".len()).any(|w| w == b"TOPSECRET"));
    }

    #[test]
    fn tampered_seal_fails() {
        let mut sealed = seal(&key(), b"data").unwrap();
        if let Some(last) = sealed.last_mut() {
            *last ^= 0xFF;
        }
        assert!(matches!(open(&key(), &sealed), Err(SecurityError::Decryption)));
    }

    #[test]
    fn wrong_version_rejected() {
        let mut sealed = seal(&key(), b"data").unwrap();
        sealed[0] = 99;
        assert!(matches!(
            open(&key(), &sealed),
            Err(SecurityError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn empty_blob_rejected() {
        assert!(matches!(
            open(&key(), &[]),
            Err(SecurityError::CiphertextTooShort)
        ));
    }

    #[test]
    fn optional_fields_roundtrip() {
        let enc = seal_opt(&key(), Some("secret")).unwrap();
        assert_eq!(
            open_opt(&key(), enc.as_deref()).unwrap(),
            Some("secret".to_owned())
        );
        let none = seal_opt(&key(), None).unwrap();
        assert!(none.is_none());
        assert!(open_opt(&key(), None).unwrap().is_none());
    }
}
