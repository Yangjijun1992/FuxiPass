//! 安全错误类型。密码学/密钥操作的统一错误枚举。
//!
//! 遵循 skill 约定：库代码用 `thiserror` 派生，函数返回 `Result<_, SecurityError>`，
//! 不使用 `panic!`、`unwrap`、`expect`（由 clippy lint 强制）。

use thiserror::Error;

/// SecurityCore 所有操作的统一错误类型。
#[derive(Debug, Error)]
pub enum SecurityError {
    /// Argon2id 参数不合法（内存/迭代/并行度越界，或 salt 过短）。
    #[error("invalid Argon2id parameters: {0}")]
    InvalidKdf(String),

    /// 主密码为空（不满足最小强度策略）。
    #[error("master password must not be empty")]
    EmptyMasterPassword,

    /// 密钥派生失败（底层 argon2 错误）。
    #[error("Argon2id key derivation failed")]
    KeyDerivation,

    /// 加密失败（AEAD 加密错误）。
    #[error("AES-256-GCM encryption failed")]
    Encryption,

    /// 解密失败（AEAD 认证失败，通常意味着密文被篡改或密钥错误）。
    #[error("AES-256-GCM decryption/authentication failed")]
    Decryption,

    /// Base64 解码失败。
    #[error("invalid base64: {0}")]
    InvalidBase64(#[from] base64::DecodeError),

    /// 恢复密钥字符串解析失败。
    #[error("invalid recovery key format")]
    InvalidRecoveryKey,

    /// JSON 序列化/反序列化失败。
    #[error("JSON serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// 包裹版本不兼容。
    #[error("unsupported wrap version, expected {expected}, got {got}")]
    VersionMismatch { expected: u32, got: u32 },

    /// GCM nonce 长度不符（必须为 12 字节）。
    #[error("GCM nonce must be {expected} bytes, got {got}")]
    InvalidNonce { expected: usize, got: usize },

    /// 密文数据过短（无法容纳认证标签）。
    #[error("ciphertext too short")]
    CiphertextTooShort,
}
