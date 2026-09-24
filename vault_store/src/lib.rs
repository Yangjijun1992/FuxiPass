//! 安全密码管家数据层（vault_store）。
//!
//! 职责：
//! - SQLite 表结构（meta / accounts / secret_fields / audit_logs，对照 docs/04）。
//! - 字段级 AES-256-GCM 加密：所有敏感列在写入前加密，DB 文件中无明文。
//! - 账号卡片 Repository：CRUD、检索、高敏感字段揭示、审计。
//!
//! 注：PC 原型的静态加密由应用层字段级加密承担（DEK 不入库）；
//! SQLCipher 数据库级加密列为移动端生产加固项（见 docs/01 §10）。

pub mod accounts;
pub mod accounts_read;
pub mod audit;
pub mod error;
pub mod models;
pub mod schema;
pub mod util;
pub mod vault;

pub use error::VaultError;
pub use models::{
    masked_preview, AccountDetail, AccountInput, AccountSummary, AuditEntry, FieldType, Importance,
    SecretFieldView,
};
pub use vault::{initialize, recover, unlock, verify_master_password, InitResult, Vault};
