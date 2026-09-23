//! 密钥新材料类型。用 distinct newtype 隔离不同语义的 256-bit 密钥，
//! 使编译器拒绝把 DEK 当 KEK、把 RecoveryKey 当 AccountKey 等混用。
//!
//! 安全约定：此类**不实现** `Debug`，避免密钥被意外写进日志。

use base32::Alphabet;
use zeroize::Zeroizing;

use crate::cipher::CryptoRng;
use crate::error::SecurityError;

/// 统一生成 32 字节（256-bit）随机密钥材料。
fn rand_u8x32() -> Zeroizing<[u8; 32]> {
    let mut arr = [0u8; 32];
    CryptoRng::fill(&mut arr);
    Zeroizing::new(arr)
}

/// 将任意字节填入 32 字节 Zeroizing 数组（长度不符则报错）。
fn to_u8x32(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, SecurityError> {
    let mut out = Zeroizing::new([0u8; 32]);
    if bytes.len() != 32 {
        return Err(SecurityError::InvalidKdf(format!(
            "expected 32-byte key, got {}",
            bytes.len()
        )));
    }
    out.copy_from_slice(bytes);
    Ok(out)
}

macro_rules! secret_key_type {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name(Zeroizing<[u8; 32]>);

        impl $name {
            /// 生成一个 256-bit 加密随机密钥。
            pub fn generate() -> Self {
                Self(rand_u8x32())
            }

            /// 从精确 32 字节构造（供解密/解包返回）。
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, SecurityError> {
                Ok(Self(to_u8x32(bytes)?))
            }

            /// 按字节切片访问（不可变借用）。
            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_ref()
            }

            /// 按 32 字节数组引用访问（供 AEAD 密钥用）。
            pub fn as_array(&self) -> &[u8; 32] {
                &*self.0
            }
        }
    };
}

secret_key_type!(Kek, "Key Encryption Key：由主密码经 Argon2id 派生，用于包裹/解包 DEK。不在库中持久化。");
secret_key_type!(Dek, "Data Encryption Key：256-bit 随机生成，实际加密全量数据，被 KEK/RecoveryKey 包裹后持有。");
secret_key_type!(AccountKey, "Account Key：存于 OS Keystore/Keychain，受生物识别与 TEE 保护，用于快捷解锁短期会话。");

/// 灾难恢复密钥（≥256-bit 熵）。用户离线保管，用于主密码遗忘时解开 DEK。
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryKey(Zeroizing<[u8; 32]>);

impl RecoveryKey {
    /// 生成一个 256-bit 随机恢复密钥。
    pub fn generate() -> Self {
        Self(rand_u8x32())
    }

    /// 从精确 32 字节构造。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SecurityError> {
        Ok(Self(to_u8x32(bytes)?))
    }

    /// 按字节切片访问。
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// 按 32 字节数组引用访问。
    pub fn as_array(&self) -> &[u8; 32] {
        &*self.0
    }

    /// 渲染成人类可读、便于抄录的分组字符串（Crockford Base32，4 字符一组以 `-` 分隔）。
    ///
    /// Crockford 字母表避免易混淆字符（0/O、1/I/L），适合抄写。
    pub fn to_display(&self) -> String {
        let encoded = base32::encode(Alphabet::Crockford, self.as_bytes());
        encoded
            .chars()
            .collect::<Vec<char>>()
            .chunks(4)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<String>>()
            .join("-")
    }

    /// 解析用户输入的显示字符串（忽略大小写、分隔符与空白），校验为 32 字节。
    pub fn from_display(s: &str) -> Result<Self, SecurityError> {
        let cleaned: String = s
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_uppercase();
        let decoded = base32::decode(Alphabet::Crockford, &cleaned)
            .ok_or(SecurityError::InvalidRecoveryKey)?;
        if decoded.len() != 32 {
            return Err(SecurityError::InvalidRecoveryKey);
        }
        Self::from_bytes(&decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::Base64Bytes;

    #[test]
    fn recovery_display_roundtrips() {
        let key = RecoveryKey::generate();
        let display = key.to_display();
        let parsed = RecoveryKey::from_display(&display).unwrap();
        assert_eq!(key.as_bytes(), parsed.as_bytes());
    }

    #[test]
    fn recovery_display_is_whitespace_and_separator_tolerant() {
        let key = RecoveryKey::generate();
        let display = key.to_display();
        let messy = display.replace('-', "").to_lowercase();
        let parsed = RecoveryKey::from_display(&messy).unwrap();
        assert_eq!(key.as_bytes(), parsed.as_bytes());
    }

    #[test]
    fn recovery_display_is_grouped() {
        let key = RecoveryKey::generate();
        let display = key.to_display();
        // base32(Crockford) of 32 bytes = 52 chars，恰好每 4 字符一组 → 13 组。
        let groups: Vec<&str> = display.split('-').collect();
        assert_eq!(groups.len(), 13);
        assert!(groups.iter().all(|g| !g.is_empty() && g.len() <= 4));
    }

    #[test]
    fn invalid_recovery_string_rejected() {
        assert!(RecoveryKey::from_display("not-a-valid-key!!").is_err());
    }

    #[test]
    fn der_from_bytes_requires_32_bytes() {
        assert!(Kek::from_bytes(&[0u8; 16]).is_err());
        assert!(Kek::from_bytes(&[0u8; 32]).is_ok());
    }

    #[test]
    fn key_types_are_distinct_compilation_units() {
        let d = Dek::generate();
        let _k = Kek::from_bytes(d.as_bytes()).unwrap();
        let _a = AccountKey::generate();
        let _r = RecoveryKey::from_bytes(d.as_bytes()).unwrap();
    }

    #[test]
    fn salt_encodes_through_base64() {
        let b = Base64Bytes::from(vec![0u8, 1, 2, 3]);
        let json = serde_json::to_string(&b).unwrap();
        assert!(json.starts_with('"'));
        let back: Base64Bytes = serde_json::from_str(&json).unwrap();
        assert_eq!(b.as_ref(), back.as_ref());
    }
}
