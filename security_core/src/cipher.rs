//! AES-256-GCM 认证加密 + 系统级加密随机数。
//!
//! 每次加密使用独立随机 96-bit nonce；返回 `(nonce, ciphertext||tag)`。
//! 解密时校验认证标签，任何篡改都会返回 `SecurityError::Decryption`。

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::SecurityError;

/// GCM 标准 nonce 长度（96-bit = 12 字节）。
pub const NONCE_LEN: usize = 12;
/// GCM 认证标签长度（128-bit = 16 字节）。
pub const TAG_LEN: usize = 16;

/// 加密随机源封装。内部使用操作系统 CSPRNG（`OsRng`）。
pub struct CryptoRng;

impl CryptoRng {
    /// 生成 `n` 字节加密随机数。
    pub fn bytes(n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        Self::fill(&mut buf);
        buf
    }

    /// 填充缓冲区为加密随机数。
    pub fn fill(dst: &mut [u8]) {
        OsRng.fill_bytes(dst);
    }
}

/// 用 256-bit 密钥对 `plaintext` 做 AES-256-GCM 加密。
///
/// 返回 `(nonce, ciphertext_with_tag)`；调用方负责分别存储 nonce 与密文。
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SecurityError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    CryptoRng::fill(&mut nonce_bytes);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| SecurityError::Encryption)?;
    Ok((nonce_bytes.to_vec(), ct))
}

/// 用 256-bit 密钥解密 AES-256-GCM 密文（`ciphertext` 须含末尾 tag）。
pub fn decrypt(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, SecurityError> {
    if nonce.len() != NONCE_LEN {
        return Err(SecurityError::InvalidNonce {
            expected: NONCE_LEN,
            got: nonce.len(),
        });
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| SecurityError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn roundtrip_preserves_plaintext() {
        let (nonce, ct) = encrypt(&key(), b"secret payload").unwrap();
        let out = decrypt(&key(), &nonce, &ct).unwrap();
        assert_eq!(out, b"secret payload");
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let (nonce, mut ct) = encrypt(&key(), b"secret").unwrap();
        ct[0] ^= 0xFF;
        assert!(matches!(
            decrypt(&key(), &nonce, &ct),
            Err(SecurityError::Decryption)
        ));
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let (nonce, ct) = encrypt(&key(), b"secret").unwrap();
        let wrong = [9u8; 32];
        assert!(matches!(
            decrypt(&wrong, &nonce, &ct),
            Err(SecurityError::Decryption)
        ));
    }

    #[test]
    fn nonce_is_unique_across_encryptions() {
        let (n1, _) = encrypt(&key(), b"same").unwrap();
        let (n2, _) = encrypt(&key(), b"same").unwrap();
        assert_ne!(n1, n2);
    }

    #[test]
    fn invalid_nonce_length_rejected() {
        let (_, ct) = encrypt(&key(), b"x").unwrap();
        assert!(matches!(
            decrypt(&key(), &[0u8; 8], &ct),
            Err(SecurityError::InvalidNonce { .. })
        ));
    }
}
