//! 高敏感字段独立密钥 FDEK（T2.2，PRD §2.1 / ADR-003）。
//!
//! # 为什么
//!
//! 若所有字段都由 DEK 加密，则「DEK 一旦泄露 = 全部字段可解」。
//! FDEK 把这层保护从 DEK 中剥离：
//!
//! ```text
//! FDEK（随机 256-bit）
//!   ├── 由 FDEK-KEK 封装 ────────> meta.fdek_wrap            （主密码 / 二次验证）
//!   └── 由恢复密钥封装 ──────────> meta.fdek_wrap_recovery   （找回重置时重新封装）
//! FDEK-KEK = Argon2id(主密码, 独立 salt/参数)
//! ```
//!
//! **为什么需要两份包裹**：若只按主密码封装，用户「忘记主密码 → 恢复密钥重置」
//! 后将再也无法解包 FDEK，高敏感字段永久丢失。恢复密钥封装使重置流程能够重新封装。
//!
//! **高敏感字段**（二级密码 / 支付密码 / 密钥，见 [`FieldType::requires_second_factor`]）
//! 由 FDEK 加密；而 FDEK 只在**二次验证（重新输入主密码）**时解包并短时缓存。
//! 因此即便攻击者取得了内存中的 DEK，也无法读取高敏感字段。

use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use security_core::{seal, KdfParams, Wrap};
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::models::FieldType;

/// 二次验证解锁后的 FDEK 短时缓存。
#[derive(Default)]
pub struct FdekCache {
    inner: Mutex<Option<Zeroizing<[u8; 32]>>>,
}

impl FdekCache {
    /// 写入缓存（覆盖旧值）。
    pub fn set(&self, key: Zeroizing<[u8; 32]>) {
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = Some(key);
    }

    /// 读取缓存（克隆一份；原值在缓存中保持被 zeroize 保护）。
    pub fn get(&self) -> Option<Zeroizing<[u8; 32]>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// 清除缓存（应在二次验证会话过期时调用）。
    pub fn clear(&self) {
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// 当前是否已解锁 FDEK。
    pub fn is_unlocked(&self) -> bool {
        self.get().is_some()
    }
}

/// 生成 32 字节随机 FDEK。
fn random_fdek() -> Zeroizing<[u8; 32]> {
    let bytes = security_core::cipher::CryptoRng::bytes(32);
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&bytes);
    key
}

fn to_array32(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    if bytes.len() != 32 {
        return Err(VaultError::InvalidInput(
            "FDEK 长度必须为 32 字节".to_owned(),
        ));
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(bytes);
    Ok(key)
}

/// `meta` 是否已存在 FDEK 包裹。
pub(crate) fn wrap_exists(conn: &Connection) -> Result<bool, VaultError> {
    let row: Option<Option<String>> = conn
        .query_row("SELECT fdek_wrap FROM meta WHERE id = 1", [], |r| r.get(0))
        .optional()?;
    Ok(row.flatten().is_some())
}

/// 用主密码解包 FDEK；返回 `None` 表示主密码错误或尚未初始化 FDEK。
pub(crate) fn unwrap_fdek(
    conn: &Connection,
    master_password: &str,
) -> Result<Option<Zeroizing<[u8; 32]>>, VaultError> {
    let row: Option<(Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT fdek_kdf, fdek_wrap FROM meta WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((Some(kdf_json), Some(wrap_json))) = row else {
        return Ok(None);
    };
    let kdf: KdfParams = serde_json::from_str(&kdf_json)?;
    let wrap: Wrap = serde_json::from_str(&wrap_json)?;
    let kek = kdf.derive_kek(master_password.as_bytes())?;
    match security_core::wrap::unwrap_with_key(kek.as_array(), &wrap) {
        Ok(bytes) => Ok(Some(to_array32(&bytes)?)),
        Err(_) => Ok(None),
    }
}

/// 首次初始化 FDEK：生成、封装，并把既有高敏感字段**事务化**重封装为 FDEK。
///
/// 仅当 `meta.fdek_wrap` 为空时调用（即在 `unlock` 中、已持有主密码与 DEK）。
/// FDEK 包裹集合：`(fdek, kdf 参数, 主密码包裹, 恢复密钥包裹)`。
pub(crate) type FdekWraps = (Zeroizing<[u8; 32]>, KdfParams, Wrap, Wrap);

/// 生成 FDEK 并产出「主密码包裹 + 恢复密钥包裹」（纯计算，不写库）。
pub(crate) fn create_fdek_wraps(
    master_password: &str,
    recovery: &security_core::RecoveryKey,
) -> Result<FdekWraps, VaultError> {
    let fdek = random_fdek();
    let kdf = KdfParams::with_random_salt();
    let kek = kdf.derive_kek(master_password.as_bytes())?;
    let wrap = security_core::wrap::wrap_with_key(kek.as_array(), Some(kdf.clone()), &*fdek)?;
    let wrap_recovery = security_core::wrap_dek_via_recovery(recovery, &fdek_key_as_dek(&fdek)?)?;
    Ok((fdek, kdf, wrap, wrap_recovery))
}

/// 迁移路径：为已存在的库启用 FDEK（重封装既有字段 + 写元数据，事务化）。
pub(crate) fn setup_fdek(
    conn: &Connection,
    master_password: &str,
    dek: &[u8; 32],
    recovery_key_display: &str,
) -> Result<(), VaultError> {
    let recovery = security_core::RecoveryKey::from_display(recovery_key_display)
        .map_err(|_| VaultError::RecoveryFailed)?;
    let (fdek, kdf, wrap, wrap_recovery) = create_fdek_wraps(master_password, &recovery)?;

    // 事务：重封装 + 元数据写入必须原子完成，避免出现「一半 FDEK、一半 DEK」的混合状态。
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let outcome = (|| -> Result<(), VaultError> {
        reseal_high_sensitivity(conn, dek, &fdek)?;
        conn.execute(
            "UPDATE meta SET fdek_kdf = ?1, fdek_wrap = ?2, fdek_wrap_recovery = ?3 WHERE id = 1",
            params![
                serde_json::to_string(&kdf)?,
                serde_json::to_string(&wrap)?,
                serde_json::to_string(&wrap_recovery)?
            ],
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(err)
        }
    }
}

/// 用恢复密钥解包 FDEK（找回重置流程使用）。
pub(crate) fn unwrap_fdek_via_recovery(
    conn: &Connection,
    recovery_key_display: &str,
) -> Result<Option<Zeroizing<[u8; 32]>>, VaultError> {
    let wrap_json: Option<Option<String>> = conn
        .query_row(
            "SELECT fdek_wrap_recovery FROM meta WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let Some(Some(wrap_json)) = wrap_json else {
        return Ok(None);
    };
    let recovery = security_core::RecoveryKey::from_display(recovery_key_display)
        .map_err(|_| VaultError::RecoveryFailed)?;
    let wrap: Wrap = serde_json::from_str(&wrap_json)?;
    let raw = security_core::wrap::unwrap_with_key(recovery.as_array(), &wrap)
        .map_err(|_| VaultError::RecoveryFailed)?;
    Ok(Some(to_array32(&raw)?))
}

/// 用新的主密码重新封装 FDEK 的主密码包裹（改密 / 恢复后必须调用）。
pub(crate) fn rewrap_fdek_for_password(
    conn: &Connection,
    fdek: &[u8; 32],
    new_master_password: &str,
) -> Result<(), VaultError> {
    let kdf = KdfParams::with_random_salt();
    let kek = kdf.derive_kek(new_master_password.as_bytes())?;
    let wrap = security_core::wrap::wrap_with_key(kek.as_array(), Some(kdf.clone()), fdek)?;
    conn.execute(
        "UPDATE meta SET fdek_kdf = ?1, fdek_wrap = ?2 WHERE id = 1",
        params![serde_json::to_string(&kdf)?, serde_json::to_string(&wrap)?],
    )?;
    Ok(())
}

/// 用新的恢复密钥重封装 FDEK 的恢复包裹（重新生成恢复密钥时必须调用）。
pub(crate) fn rewrap_fdek_for_recovery(
    conn: &Connection,
    fdek: &[u8; 32],
    recovery: &security_core::RecoveryKey,
) -> Result<(), VaultError> {
    let wrap_recovery =
        security_core::wrap_dek_via_recovery(recovery, &fdek_key_as_dek(&Zeroizing::new(*fdek))?)?;
    conn.execute(
        "UPDATE meta SET fdek_wrap_recovery = ?1 WHERE id = 1",
        params![serde_json::to_string(&wrap_recovery)?],
    )?;
    Ok(())
}

/// 把 32 字节 FDEK 临时视为 DEK 以便复用恢复密钥封装函数。
///
/// `Dek` 只是 `Zeroizing<[u8;32]>` 的语义新类型；此处仅用于封装 API 参数，
/// 不改变 FDEK 的语义。长度恒为 32，构造不可能失败。
fn fdek_key_as_dek(fdek: &Zeroizing<[u8; 32]>) -> Result<security_core::Dek, VaultError> {
    Ok(security_core::Dek::from_bytes(&**fdek)?)
}

/// 把全部「需二次验证」字段从 DEK 重封装为 FDEK。
fn reseal_high_sensitivity(
    conn: &Connection,
    dek: &[u8; 32],
    fdek: &[u8; 32],
) -> Result<(), VaultError> {
    let mut stmt = conn.prepare("SELECT id, field_type, sealed FROM secret_fields")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut updates: Vec<(String, Vec<u8>)> = Vec::new();
    for row in rows {
        let (id, field_type, sealed) = row?;
        let Some(ft) = FieldType::parse(&field_type) else {
            continue;
        };
        if ft.requires_second_factor() {
            let plain = seal::open(dek, &sealed)?;
            updates.push((id, seal::seal(fdek, &plain)?));
        }
    }
    drop(stmt);
    for (id, sealed) in updates {
        conn.execute(
            "UPDATE secret_fields SET sealed = ?1 WHERE id = ?2",
            params![sealed, id],
        )?;
    }
    Ok(())
}
