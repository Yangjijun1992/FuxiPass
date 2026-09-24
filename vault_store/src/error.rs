//! vault_store 统一错误类型。

use thiserror::Error;

/// 数据层错误。
#[derive(Debug, Error)]
pub enum VaultError {
    /// 加解密/密钥错误（来自 security_core）。
    #[error("crypto error: {0}")]
    Crypto(#[from] security_core::SecurityError),

    /// SQLite 错误。
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// 保险库尚未初始化（缺 meta 行）。
    #[error("vault is not initialized")]
    NotInitialized,

    /// 目标文件已存在，拒绝覆盖（防误初始化导致数据丢失）。
    #[error("vault already exists at this path")]
    AlreadyExists,

    /// 账号卡片不存在。
    #[error("account not found: {0}")]
    AccountNotFound(String),

    /// 高敏感字段不存在。
    #[error("secret field not found: {0}")]
    SecretNotFound(String),

    /// 输入不合法。
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// 恢复密钥错误或包裹损坏。
    #[error("recovery failed: invalid recovery key or corrupted wrap")]
    RecoveryFailed,

    /// 文件系统错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON 序列化错误。
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}
