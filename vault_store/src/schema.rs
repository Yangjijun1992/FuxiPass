//! SQLite 表结构与建库/迁移逻辑（对照 docs/04 §1）。
//!
//! 所有敏感列在写入前由应用层用 DEK 做 AES-256-GCM 字段级加密，
//! 因此即便数据库文件被拷贝，也读不到任何明文。
//!
//! 版本历史：
//! - v1：初始结构。
//! - v2：`meta` 增加 `failed_attempts` / `locked_until`，用于防爆破退避锁定（T2.3）。

use rusqlite::Connection;

use crate::VaultError;

/// 当前 schema 版本，便于后续迁移。
pub const SCHEMA_VERSION: i64 = 2;

const SCHEMA_SQL: &str = r"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version  INTEGER NOT NULL,
    kdf_params      TEXT    NOT NULL,
    dekwrap         TEXT    NOT NULL,
    recoverywrap    TEXT,
    hint            TEXT,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    id            TEXT PRIMARY KEY,
    app_name_enc  BLOB    NOT NULL,
    url_enc       BLOB,
    username_enc  BLOB,
    notes_enc     BLOB,
    importance    TEXT    NOT NULL,
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS secret_fields (
    id                     TEXT PRIMARY KEY,
    account_id             TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    field_type             TEXT NOT NULL,
    sealed                 BLOB NOT NULL,
    masked_preview         TEXT NOT NULL,
    requires_second_factor INTEGER NOT NULL,
    created_at             TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_secret_account ON secret_fields(account_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT NOT NULL,
    operation      TEXT NOT NULL,
    field_category TEXT,
    account_id     TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);
";

/// 应用建表语句（幂等）。
pub fn apply(conn: &Connection) -> Result<(), VaultError> {
    conn.execute_batch(SCHEMA_SQL)?;
    Ok(())
}

/// 判断库是否已完成初始化（存在 meta 表）。
pub fn is_initialized(conn: &Connection) -> Result<bool, VaultError> {
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
        [],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// 把旧版本数据库迁移到当前版本（幂等；未初始化的库直接跳过）。
pub fn migrate(conn: &Connection) -> Result<(), VaultError> {
    if !is_initialized(conn)? {
        return Ok(());
    }
    let version: i64 = conn.query_row(
        "SELECT schema_version FROM meta WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    if version < 2 {
        conn.execute_batch(
            "ALTER TABLE meta ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE meta ADD COLUMN locked_until TEXT;",
        )?;
        conn.execute("UPDATE meta SET schema_version = 2 WHERE id = 1", [])?;
    }
    Ok(())
}
