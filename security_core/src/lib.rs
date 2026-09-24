//! 安全密码管家 SecurityCore —— 加密与密钥体系的核心库。
//!
//! 对照文档：
//! - `docs/01-架构规格书.md` §4 密钥体系、§5 安全核心层
//! - `docs/04-数据库与远程接口.md` §1.1 包裹格式
//!
//! # 安全设计要点
//! * 主密码永不直接加密数据：经 Argon2id 派生 KEK，KEK 只包裹 DEK。
//! * 全量数据用随机 DEK（AES-256-GCM）加密；改主密码只重包 DEK，不重加密全量。
//! * 恢复密钥（RecoveryKey）以 `None` 形式包裹 DEK，用于忘记主密码时解包。
//! * 所有密钥材料用 `zeroize::Zeroizing` 包裹，不实现 `Debug`，避免泄露到日志。

pub mod bytes;
pub mod cipher;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod seal;
pub mod vault;
pub mod wrap;

pub use error::SecurityError;
pub use kdf::KdfParams;
pub use keys::{AccountKey, Dek, Kek, RecoveryKey};
pub use seal::{open as open_sealed, seal};
pub use vault::{
    change_master_password, derive_kek, generate_dek, generate_recovery_key, recover_and_reset,
    unwrap_dek, unwrap_dek_via_recovery, wrap_dek, wrap_dek_via_recovery,
};
pub use wrap::{CipherAlgorithm, CipherParams, Wrap};
