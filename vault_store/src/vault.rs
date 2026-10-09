//! 保险库生命周期：初始化、解锁、恢复、修改主密码、密码提示词。
//!
//! 对应 PRD §2.1（密钥体系）与 §2.2（恢复/重置）。

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use security_core::{Dek, KdfParams, RecoveryKey, Wrap};

use crate::error::VaultError;
use crate::fdek;
use crate::lockout;
use crate::models::FieldType;
use crate::schema::{self, SCHEMA_VERSION};
use crate::util::{now_millis, now_millis_u64};

/// 已解锁的保险库：持有 SQLite 连接、DEK 与（可选的）FDEK 缓存。
pub struct Vault {
    pub(crate) conn: Connection,
    pub(crate) dek: Dek,
    /// 高敏感字段密钥缓存；仅在二次验证后存在（见 `fdek.rs`）。
    pub(crate) fdek: fdek::FdekCache,
    /// 本库是否已启用 FDEK（v3 特性；旧库为 `false`，保持 DEK 兼容模式）。
    pub(crate) has_fdek: bool,
}

impl Vault {
    /// 字段级加密使用的 256-bit 密钥引用。
    pub(crate) fn key(&self) -> &[u8; 32] {
        self.dek.as_array()
    }

    /// 本库是否已启用 FDEK（高敏感字段独立密钥）。
    pub const fn has_fdek(&self) -> bool {
        self.has_fdek
    }

    /// 显式启用 FDEK（v2 → v3 迁移）。
    ///
    /// **必须同时提供主密码与恢复密钥**：主密码用于封装 FDEK（二次验证），
    /// 恢复密钥用于建立第二份包裹，否则用户一旦忘记主密码将无法恢复高敏感字段。
    /// 迁移在事务内完成：要么全部字段重封装成功，要么完全不动。
    pub fn enable_fdek(
        &mut self,
        master_password: &str,
        recovery_key_display: &str,
    ) -> Result<(), VaultError> {
        if self.has_fdek {
            return Err(VaultError::InvalidInput("FDEK 已启用".to_owned()));
        }
        fdek::setup_fdek(
            &self.conn,
            master_password,
            self.dek.as_array(),
            recovery_key_display,
        )?;
        self.has_fdek = true;
        Ok(())
    }

    /// 二次验证：用主密码解包 FDEK 并缓存。
    ///
    /// 返回 `false` 表示主密码错误（会计入退避锁定）。成功后高敏感字段
    /// 的读写才被允许——这正是「DEK 泄露也不暴露支付密码」的实现点。
    pub fn unlock_second_factor(&self, master_password: &str) -> Result<bool, VaultError> {
        let now_ms = now_millis_u64();
        let status = lockout::status_of(&self.conn, now_ms)?;
        if status.locked {
            return Err(VaultError::Locked {
                remaining_secs: status.remaining_secs,
            });
        }
        if self.has_fdek {
            return match fdek::unwrap_fdek(&self.conn, master_password)? {
                Some(key) => {
                    self.fdek.set(key);
                    lockout::reset(&self.conn)?;
                    Ok(true)
                }
                None => {
                    if let Some(remaining_secs) = lockout::register_failure(&self.conn, now_ms)? {
                        return Err(VaultError::Locked { remaining_secs });
                    }
                    Ok(false)
                }
            };
        }
        // 兼容模式（尚未启用 FDEK）：以 DEK 包裹校验主密码，语义保持一致。
        let (kdf_json, dekwrap_json) = read_kdf_and_dekwrap(&self.conn)?;
        let kdf: KdfParams = serde_json::from_str(&kdf_json)?;
        let dekwrap: Wrap = serde_json::from_str(&dekwrap_json)?;
        let verified = kdf
            .derive_kek(master_password.as_bytes())
            .ok()
            .is_some_and(|kek| security_core::unwrap_dek(&kek, &dekwrap).is_ok());
        if verified {
            lockout::reset(&self.conn)?;
        } else if let Some(remaining_secs) = lockout::register_failure(&self.conn, now_ms)? {
            return Err(VaultError::Locked { remaining_secs });
        }
        Ok(verified)
    }

    /// 结束二次验证会话（清除 FDEK 缓存）。
    pub fn lock_second_factor(&self) {
        self.fdek.clear();
    }

    /// 当前是否已解锁高敏感字段（二次验证有效）。
    pub fn is_second_factor_unlocked(&self) -> bool {
        self.fdek.is_unlocked()
    }

    /// 按字段敏感度选择密钥进行封装。
    pub(crate) fn seal_secret(
        &self,
        field_type: FieldType,
        value: &str,
    ) -> Result<Vec<u8>, VaultError> {
        if self.has_fdek && field_type.requires_second_factor() {
            let key = self.fdek.get().ok_or(VaultError::SecondFactorRequired)?;
            security_core::seal::seal(&key, value.as_bytes()).map_err(VaultError::from)
        } else {
            security_core::seal::seal(self.dek.as_array(), value.as_bytes())
                .map_err(VaultError::from)
        }
    }

    /// 按字段敏感度选择密钥进行解封。
    pub(crate) fn open_secret(
        &self,
        field_type: FieldType,
        sealed: &[u8],
    ) -> Result<String, VaultError> {
        let bytes = if self.has_fdek && field_type.requires_second_factor() {
            let key = self.fdek.get().ok_or(VaultError::SecondFactorRequired)?;
            security_core::seal::open(&key, sealed)?
        } else {
            security_core::seal::open(self.dek.as_array(), sealed)?
        };
        String::from_utf8(bytes)
            .map_err(|_| VaultError::Crypto(security_core::SecurityError::Decryption))
    }

    /// 修改主密码：仅重包 DEK（不重加密全量数据）。
    pub fn change_master_password(&mut self, new_password: &str) -> Result<(), VaultError> {
        if new_password.is_empty() {
            return Err(VaultError::InvalidInput(
                "new master password must not be empty".to_owned(),
            ));
        }
        // 启用 FDEK 后，改密必须同时重封装 FDEK；因此要求二次验证已解锁。
        let fdek_key = if self.has_fdek {
            Some(self.fdek.get().ok_or(VaultError::SecondFactorRequired)?)
        } else {
            None
        };
        let new_kdf = KdfParams::with_random_salt();
        let new_kek = new_kdf.derive_kek(new_password.as_bytes())?;
        let new_dekwrap = security_core::wrap_dek(&new_kek, &self.dek, Some(new_kdf.clone()))?;
        self.conn.execute(
            "UPDATE meta SET kdf_params = ?1, dekwrap = ?2 WHERE id = 1",
            params![
                serde_json::to_string(&new_kdf)?,
                serde_json::to_string(&new_dekwrap)?
            ],
        )?;
        if let Some(key) = fdek_key {
            fdek::rewrap_fdek_for_password(&self.conn, &key, new_password)?;
        }
        self.record_audit("change_master_password", None, None)?;
        Ok(())
    }

    /// 设置密码提示词（纯本地，应避免包含密码本身）。
    pub fn set_hint(&self, hint: Option<&str>) -> Result<(), VaultError> {
        self.conn
            .execute("UPDATE meta SET hint = ?1 WHERE id = 1", params![hint])?;
        Ok(())
    }

    /// 读取密码提示词。
    pub fn hint(&self) -> Result<Option<String>, VaultError> {
        let hint: Option<String> = self
            .conn
            .query_row("SELECT hint FROM meta WHERE id = 1", [], |row| row.get(0))
            .optional()?
            .flatten();
        Ok(hint)
    }

    /// 重新生成恢复密钥（需已解锁）。返回新的显示串，**旧恢复密钥立即失效**。
    ///
    /// 启用 FDEK 后本操作需要二次验证：必须同时更新 FDEK 的恢复包裹，
    /// 否则用户日后用新恢复密钥重置主密码时将无法解包 FDEK（**数据丢失**）。
    pub fn regenerate_recovery_key(&self) -> Result<String, VaultError> {
        let fdek_key = if self.has_fdek {
            Some(self.fdek.get().ok_or(VaultError::SecondFactorRequired)?)
        } else {
            None
        };
        let recovery = security_core::generate_recovery_key();
        let recoverywrap = security_core::wrap_dek_via_recovery(&recovery, &self.dek)?;
        self.conn.execute(
            "UPDATE meta SET recoverywrap = ?1 WHERE id = 1",
            params![serde_json::to_string(&recoverywrap)?],
        )?;
        if let Some(key) = fdek_key {
            fdek::rewrap_fdek_for_recovery(&self.conn, &key, &recovery)?;
        }
        self.record_audit("regenerate_recovery_key", None, None)?;
        Ok(recovery.to_display())
    }
}

/// 读取密码提示词（**无需解锁**：提示词以明文存于 meta，供解锁界面显示）。
///
/// 主密码遗忘时用户需要看到提示词，因此该读取不能依赖解锁会话。
pub fn read_hint(path: &Path) -> Result<Option<String>, VaultError> {
    if !path.exists() {
        return Err(VaultError::NotInitialized);
    }
    let conn = open_connection(path)?;
    let hint: Option<Option<String>> = conn
        .query_row("SELECT hint FROM meta WHERE id = 1", [], |row| row.get(0))
        .optional()?;
    Ok(hint.flatten())
}

/// 打开数据库连接，启用外键约束并执行 schema 迁移。
///
/// 外键约束是**每连接**生效的：级联删除依赖它，遗漏会导致孤儿数据。
pub(crate) fn open_connection(path: &Path) -> Result<Connection, VaultError> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    schema::migrate(&conn)?;
    Ok(conn)
}

/// 初始化结果：新保险库的恢复密钥（需用户离线保管）。
pub struct InitResult {
    /// 人类可读、便于抄录的恢复密钥显示串。
    pub recovery_key_display: String,
}

/// 初始化一个新保险库：生成 DEK 与恢复密钥，写入包裹与 KDF 参数。
///
/// 若目标文件已存在则拒绝，避免覆盖已有数据。
pub fn initialize(path: &Path, master_password: &str) -> Result<InitResult, VaultError> {
    if path.exists() {
        return Err(VaultError::AlreadyExists);
    }
    if master_password.is_empty() {
        return Err(VaultError::InvalidInput(
            "master password must not be empty".to_owned(),
        ));
    }
    let conn = open_connection(path)?;
    schema::apply(&conn)?;

    let kdf = KdfParams::with_random_salt();
    let kek = kdf.derive_kek(master_password.as_bytes())?;
    let dek = security_core::generate_dek();
    let recovery = security_core::generate_recovery_key();
    let dekwrap = security_core::wrap_dek(&kek, &dek, Some(kdf.clone()))?;
    let recoverywrap = security_core::wrap_dek_via_recovery(&recovery, &dek)?;
    // 新库直接启用 FDEK（T2.2）：此处同时持有主密码与恢复密钥，可建立双包裹。
    let (_fdek, fdek_kdf, fdek_wrap, fdek_wrap_recovery) =
        fdek::create_fdek_wraps(master_password, &recovery)?;

    conn.execute(
        "INSERT INTO meta
         (id, schema_version, kdf_params, dekwrap, recoverywrap, hint,
          fdek_kdf, fdek_wrap, fdek_wrap_recovery, created_at)
         VALUES (1, ?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7, ?8)",
        params![
            SCHEMA_VERSION,
            serde_json::to_string(&kdf)?,
            serde_json::to_string(&dekwrap)?,
            serde_json::to_string(&recoverywrap)?,
            serde_json::to_string(&fdek_kdf)?,
            serde_json::to_string(&fdek_wrap)?,
            serde_json::to_string(&fdek_wrap_recovery)?,
            now_millis()
        ],
    )?;

    Ok(InitResult {
        recovery_key_display: recovery.to_display(),
    })
}

/// 用主密码解锁保险库。
///
/// 处于退避锁定期时返回 `Locked`；主密码错误时累计失败次数，
/// 达到阈值后进入指数退避锁定（**绝不删除或清空数据**）。
pub fn unlock(path: &Path, master_password: &str) -> Result<Vault, VaultError> {
    let conn = open_connection(path)?;
    if !schema::is_initialized(&conn)? {
        return Err(VaultError::NotInitialized);
    }
    let now_ms = now_millis_u64();

    let status = lockout::status_of(&conn, now_ms)?;
    if status.locked {
        return Err(VaultError::Locked {
            remaining_secs: status.remaining_secs,
        });
    }

    let (kdf_json, dekwrap_json) = read_kdf_and_dekwrap(&conn)?;
    let kdf: KdfParams = serde_json::from_str(&kdf_json)?;
    let dekwrap: Wrap = serde_json::from_str(&dekwrap_json)?;
    let kek = kdf.derive_kek(master_password.as_bytes())?;
    match security_core::unwrap_dek(&kek, &dekwrap) {
        Ok(dek) => {
            let has_fdek = fdek::wrap_exists(&conn)?;
            lockout::reset(&conn)?;
            Ok(Vault {
                conn,
                dek,
                fdek: fdek::FdekCache::default(),
                has_fdek,
            })
        }
        Err(_) => {
            if let Some(remaining_secs) = lockout::register_failure(&conn, now_ms)? {
                return Err(VaultError::Locked { remaining_secs });
            }
            Err(VaultError::InvalidInput(
                "incorrect master password".to_owned(),
            ))
        }
    }
}

/// 忘记主密码时，用恢复密钥重置主密码（DEK 与数据保持不变）。
///
/// 该通道**不受退避锁定限制**——否则用户一旦被锁定将无法自救；
/// 其安全性由 256-bit 恢复密钥承担。成功后清零失败计数。
pub fn recover(
    path: &Path,
    recovery_key_display: &str,
    new_master_password: &str,
) -> Result<(), VaultError> {
    if new_master_password.is_empty() {
        return Err(VaultError::InvalidInput(
            "new master password must not be empty".to_owned(),
        ));
    }
    let conn = open_connection(path)?;
    if !schema::is_initialized(&conn)? {
        return Err(VaultError::NotInitialized);
    }
    let recoverywrap_json: Option<String> = conn
        .query_row("SELECT recoverywrap FROM meta WHERE id = 1", [], |row| {
            row.get(0)
        })
        .optional()?
        .ok_or(VaultError::NotInitialized)?;
    let recoverywrap_json = recoverywrap_json.ok_or(VaultError::RecoveryFailed)?;

    let recovery =
        RecoveryKey::from_display(recovery_key_display).map_err(|_| VaultError::RecoveryFailed)?;
    let recovery_wrap: Wrap = serde_json::from_str(&recoverywrap_json)?;
    let dek = security_core::unwrap_dek_via_recovery(&recovery, &recovery_wrap)
        .map_err(|_| VaultError::RecoveryFailed)?;

    // FDEK：启用过的库必须一并重封装，否则重置后高敏感字段将永久无法解密。
    // 缺少恢复包裹时**拒绝重置**，而不是静默丢数据。
    let fdek_key = if fdek::wrap_exists(&conn)? {
        Some(
            fdek::unwrap_fdek_via_recovery(&conn, recovery_key_display)?
                .ok_or(VaultError::FdekRecoveryUnavailable)?,
        )
    } else {
        None
    };

    let new_kdf = KdfParams::with_random_salt();
    let new_kek = new_kdf.derive_kek(new_master_password.as_bytes())?;
    let new_dekwrap = security_core::wrap_dek(&new_kek, &dek, Some(new_kdf.clone()))?;
    conn.execute(
        "UPDATE meta SET kdf_params = ?1, dekwrap = ?2 WHERE id = 1",
        params![
            serde_json::to_string(&new_kdf)?,
            serde_json::to_string(&new_dekwrap)?
        ],
    )?;
    if let Some(key) = fdek_key {
        fdek::rewrap_fdek_for_password(&conn, &key, new_master_password)?;
    }
    lockout::reset(&conn)?;
    Ok(())
}

/// 校验主密码是否正确（用于高敏感操作的二次验证），不改变保险库状态。
///
/// 同样受退避锁定约束——防止攻击者借二次验证接口暴力破解。
pub fn verify_master_password(path: &Path, master_password: &str) -> Result<bool, VaultError> {
    let conn = open_connection(path)?;
    if !schema::is_initialized(&conn)? {
        return Err(VaultError::NotInitialized);
    }
    let now_ms = now_millis_u64();
    let status = lockout::status_of(&conn, now_ms)?;
    if status.locked {
        return Err(VaultError::Locked {
            remaining_secs: status.remaining_secs,
        });
    }
    let (kdf_json, dekwrap_json) = read_kdf_and_dekwrap(&conn)?;
    let kdf: KdfParams = serde_json::from_str(&kdf_json)?;
    let dekwrap: Wrap = serde_json::from_str(&dekwrap_json)?;
    let Ok(kek) = kdf.derive_kek(master_password.as_bytes()) else {
        return Ok(false);
    };
    if security_core::unwrap_dek(&kek, &dekwrap).is_ok() {
        lockout::reset(&conn)?;
        Ok(true)
    } else {
        if let Some(remaining_secs) = lockout::register_failure(&conn, now_ms)? {
            return Err(VaultError::Locked { remaining_secs });
        }
        Ok(false)
    }
}

fn read_kdf_and_dekwrap(conn: &Connection) -> Result<(String, String), VaultError> {
    conn.query_row(
        "SELECT kdf_params, dekwrap FROM meta WHERE id = 1",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )
    .optional()?
    .ok_or(VaultError::NotInitialized)
}
