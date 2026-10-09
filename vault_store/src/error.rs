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

    /// 该库已启用 FDEK 但缺少恢复密钥包裹，无法在重置主密码时重封装。
    /// 为避免**静默丢失**高敏感字段，此处直接拒绝。
    #[error("vault has FDEK but no recovery wrap; refusing password reset to avoid data loss")]
    FdekRecoveryUnavailable,

    /// 需要先完成二次验证（重新输入主密码）才能读写高敏感字段。
    #[error("second-factor verification required to access high-sensitivity fields")]
    SecondFactorRequired,

    /// 因连续输错而处于退避锁定期（**不会清除任何数据**）。
    #[error("too many failed attempts; try again in {remaining_secs} seconds")]
    Locked {
        /// 剩余锁定秒数。
        remaining_secs: u64,
    },

    /// 文件系统错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON 序列化错误。
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}
