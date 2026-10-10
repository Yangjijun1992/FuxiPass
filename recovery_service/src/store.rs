//! 绑定存储：内存实现（测试/临时）与 SQLite 实现（持久化）。
//!
//! **存储内容本身即非敏感**：联系方式哈希（不可逆）+ 恢复密钥加密的套件（密文）。
//! 因此持久化到本地文件不引入额外泄露面；但仍建议限制文件权限。
//!
//! 说明：验证码挑战与令牌**不做持久化** —— 它们本质短寿命令（5 分钟 / 2 分钟），
//! 重启后失效反而更安全。

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

use crate::{Binding, ContactType, RecoveryError};

/// 绑定存储抽象。
pub trait BindingStore: Send + Sync {
    /// 写入/覆盖绑定。
    ///
    /// # Errors
    /// 底层存储失败时返回 [`RecoveryError::Storage`]。
    fn upsert(&self, binding: &Binding) -> Result<(), RecoveryError>;

    /// 按联系方式哈希读取绑定。
    ///
    /// # Errors
    /// 底层存储失败时返回 [`RecoveryError::Storage`]。
    fn get(&self, contact_hash: &str) -> Result<Option<Binding>, RecoveryError>;

    /// 绑定总数。
    ///
    /// # Errors
    /// 底层存储失败时返回 [`RecoveryError::Storage`]。
    fn count(&self) -> Result<usize, RecoveryError>;
}

/// 内存实现（测试、或明确不需要持久化时使用）。
#[derive(Default)]
pub struct MemoryBindingStore {
    inner: Mutex<HashMap<String, Binding>>,
}

impl MemoryBindingStore {
    /// 新建空存储。
    pub fn new() -> Self {
        Self::default()
    }
}

impl BindingStore for MemoryBindingStore {
    fn upsert(&self, binding: &Binding) -> Result<(), RecoveryError> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(binding.contact_hash.clone(), binding.clone());
        Ok(())
    }

    fn get(&self, contact_hash: &str) -> Result<Option<Binding>, RecoveryError> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(contact_hash)
            .cloned())
    }

    fn count(&self) -> Result<usize, RecoveryError> {
        Ok(self.inner.lock().unwrap_or_else(|e| e.into_inner()).len())
    }
}

/// SQLite 实现：**重启不丢绑定**。
pub struct SqliteBindingStore {
    conn: Mutex<Connection>,
}

impl SqliteBindingStore {
    /// 打开（或创建）指定路径的存储文件。
    ///
    /// # Errors
    /// 文件不可读写或建表失败时返回 [`RecoveryError::Storage`]。
    pub fn open(path: &Path) -> Result<Self, RecoveryError> {
        let conn = Connection::open(path).map_err(|e| RecoveryError::Storage(e.to_string()))?;
        Self::init(conn)
    }

    /// 内存数据库（测试用）。
    ///
    /// # Errors
    /// 建表失败时返回 [`RecoveryError::Storage`]。
    pub fn in_memory() -> Result<Self, RecoveryError> {
        let conn =
            Connection::open_in_memory().map_err(|e| RecoveryError::Storage(e.to_string()))?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, RecoveryError> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS bindings (
                 contact_hash  TEXT PRIMARY KEY,
                 contact_type  TEXT NOT NULL,
                 recoverywrap  TEXT NOT NULL,
                 created_at    TEXT NOT NULL,
                 updated_at    TEXT NOT NULL
             );",
        )
        .map_err(|e| RecoveryError::Storage(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl BindingStore for SqliteBindingStore {
    fn upsert(&self, binding: &Binding) -> Result<(), RecoveryError> {
        let ts = now_millis();
        let kind = match binding.contact_type {
            ContactType::Email => "email",
            ContactType::Sms => "sms",
        };
        self.lock()
            .execute(
                "INSERT INTO bindings (contact_hash, contact_type, recoverywrap, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT(contact_hash) DO UPDATE SET
                     contact_type = excluded.contact_type,
                     recoverywrap = excluded.recoverywrap,
                     updated_at   = excluded.updated_at",
                params![binding.contact_hash, kind, binding.recoverywrap, ts],
            )
            .map_err(|e| RecoveryError::Storage(e.to_string()))?;
        Ok(())
    }

    fn get(&self, contact_hash: &str) -> Result<Option<Binding>, RecoveryError> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT contact_type, recoverywrap FROM bindings WHERE contact_hash = ?1",
                params![contact_hash],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|e| RecoveryError::Storage(e.to_string()))?;
        Ok(row.map(|(kind, recoverywrap)| Binding {
            contact_hash: contact_hash.to_owned(),
            contact_type: if kind == "sms" {
                ContactType::Sms
            } else {
                ContactType::Email
            },
            recoverywrap,
        }))
    }

    fn count(&self) -> Result<usize, RecoveryError> {
        let n: i64 = self
            .lock()
            .query_row("SELECT count(*) FROM bindings", [], |r| r.get(0))
            .map_err(|e| RecoveryError::Storage(e.to_string()))?;
        Ok(usize::try_from(n).unwrap_or(usize::MAX))
    }
}

fn now_millis() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or_else(|_| String::from("0"), |d| d.as_millis().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Binding {
        Binding {
            contact_hash: "abc123".to_owned(),
            contact_type: ContactType::Email,
            recoverywrap: "{\"ciphertext\":\"X\"}".to_owned(),
        }
    }

    #[test]
    fn sqlite_store_roundtrip() {
        let store = SqliteBindingStore::in_memory().unwrap();
        assert_eq!(store.count().unwrap(), 0);
        assert!(store.get("abc123").unwrap().is_none());

        store.upsert(&sample()).unwrap();
        assert_eq!(store.count().unwrap(), 1);
        let got = store.get("abc123").unwrap().unwrap();
        assert_eq!(got.contact_type, ContactType::Email);
        assert_eq!(got.recoverywrap, sample().recoverywrap);

        // 覆盖写入不新增记录
        let mut updated = sample();
        updated.recoverywrap = "{\"ciphertext\":\"Y\"}".to_owned();
        store.upsert(&updated).unwrap();
        assert_eq!(store.count().unwrap(), 1);
        assert_eq!(
            store.get("abc123").unwrap().unwrap().recoverywrap,
            updated.recoverywrap
        );
    }

    #[test]
    fn sqlite_store_survives_reopen() {
        let mut path = std::env::temp_dir();
        path.push(format!("fuxipass_rs_test_{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);

        {
            let store = SqliteBindingStore::open(&path).unwrap();
            store.upsert(&sample()).unwrap();
        }
        // 模拟「服务重启」：重新打开同一文件
        {
            let store = SqliteBindingStore::open(&path).unwrap();
            assert_eq!(store.count().unwrap(), 1, "重启后绑定应当仍在");
            assert!(store.get("abc123").unwrap().is_some());
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }
}
