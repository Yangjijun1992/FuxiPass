//! 防爆破退避锁定（T2.3，PRD §3.4.3）。
//!
//! **硬红线**：连续输错只导致退避锁定，**绝不删除或清空任何用户数据**。
//! 锁定状态持久化在 `meta` 表，重启后依然生效。
//!
//! 退避策略：第 5 次 → 5 分钟；第 6 次 → 10 分钟；第 7 次 → 20 分钟；
//! 第 8 次及以后 → 上限 30 分钟。

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::error::VaultError;
use crate::util::now_millis_u64;

/// 触发锁定的累计失败次数阈值。
pub const LOCK_THRESHOLD: u32 = 5;
/// 首次锁定时长（分钟）。
pub const BASE_LOCK_MINUTES: u64 = 5;
/// 锁定时长上限（分钟）。
pub const MAX_LOCK_MINUTES: u64 = 30;

const MS_PER_SECOND: u64 = 1_000;
const SECONDS_PER_MINUTE: u64 = 60;

/// 当前锁定状态（供界面显示与错误提示）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockStatus {
    /// 是否处于锁定期。
    pub locked: bool,
    /// 剩余锁定秒数（未锁定时为 0）。
    pub remaining_secs: u64,
    /// 累计失败次数（成功解锁后清零）。
    pub failed_attempts: u32,
}

fn read_counter(conn: &Connection) -> Result<(u32, Option<u64>), VaultError> {
    let (attempts, until): (i64, Option<String>) = conn
        .query_row(
            "SELECT failed_attempts, locked_until FROM meta WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(VaultError::NotInitialized)?;
    Ok((
        u32::try_from(attempts).unwrap_or(u32::MAX),
        until.and_then(|s| s.parse::<u64>().ok()),
    ))
}

/// 读取当前锁定状态。
pub(crate) fn status_of(conn: &Connection, now_ms: u64) -> Result<LockStatus, VaultError> {
    let (failed_attempts, until_ms) = read_counter(conn)?;
    let remaining_ms = until_ms.unwrap_or(0).saturating_sub(now_ms);
    Ok(LockStatus {
        locked: remaining_ms > 0,
        remaining_secs: remaining_ms.div_ceil(MS_PER_SECOND),
        failed_attempts,
    })
}

/// 记录一次失败。达到阈值时开启退避锁定，返回本次锁定的秒数。
pub(crate) fn register_failure(conn: &Connection, now_ms: u64) -> Result<Option<u64>, VaultError> {
    let (current, _) = read_counter(conn)?;
    let attempts = current.saturating_add(1);
    if attempts < LOCK_THRESHOLD {
        conn.execute(
            "UPDATE meta SET failed_attempts = ?1 WHERE id = 1",
            params![i64::from(attempts)],
        )?;
        return Ok(None);
    }
    let exponent = attempts.saturating_sub(LOCK_THRESHOLD).min(3);
    let minutes = (BASE_LOCK_MINUTES << exponent).min(MAX_LOCK_MINUTES);
    let until_ms = now_ms.saturating_add(
        minutes
            .saturating_mul(SECONDS_PER_MINUTE)
            .saturating_mul(MS_PER_SECOND),
    );
    conn.execute(
        "UPDATE meta SET failed_attempts = ?1, locked_until = ?2 WHERE id = 1",
        params![i64::from(attempts), until_ms.to_string()],
    )?;
    Ok(Some(minutes.saturating_mul(SECONDS_PER_MINUTE)))
}

/// 成功解锁后清零失败计数与锁定。
pub(crate) fn reset(conn: &Connection) -> Result<(), VaultError> {
    conn.execute(
        "UPDATE meta SET failed_attempts = 0, locked_until = NULL WHERE id = 1",
        [],
    )?;
    Ok(())
}

/// 查询锁定状态（无需主密码；供解锁界面显示剩余时间）。
pub fn lock_status(path: &Path) -> Result<LockStatus, VaultError> {
    if !path.exists() {
        return Err(VaultError::NotInitialized);
    }
    let conn = crate::vault::open_connection(path)?;
    status_of(&conn, now_millis_u64())
}
