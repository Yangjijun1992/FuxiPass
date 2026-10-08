//! 平台安全存储抽象测试（T1.4）。
//!
//! 覆盖：内存实现、文件实现、trait 对象使用、AccountKey 生命周期。
//! 原生适配器（Keystore/Keychain）需移动端工具链，其契约见 `docs/07` §4。

// 集成测试为纯测试代码，允许 unwrap/expect/panic（src/ 仍全局 deny）。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use security_core::cipher::CryptoRng;
use vault_store::secure_store::{FileSecureStore, MemorySecureStore, SecureStore};
use vault_store::ACCOUNT_KEY_ID;

/// 临时目录，析构时清理。
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "fuxipass_store_{}",
            URL_SAFE_NO_PAD.encode(CryptoRng::bytes(8))
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[test]
fn memory_store_roundtrip() {
    let store = MemorySecureStore::new();
    assert_eq!(store.load("k").unwrap(), None, "未写入应返回 None");

    store.store("k", b"secret-key-material").unwrap();
    assert_eq!(
        store.load("k").unwrap(),
        Some(b"secret-key-material".to_vec())
    );

    // 覆盖写入
    store.store("k", b"new-material").unwrap();
    assert_eq!(store.load("k").unwrap(), Some(b"new-material".to_vec()));

    store.delete("k").unwrap();
    assert_eq!(store.load("k").unwrap(), None);
    // 重复删除应静默成功
    store.delete("k").unwrap();
}

#[test]
fn file_store_roundtrip_and_delete() {
    let dir = TempDir::new();
    let store = FileSecureStore::new(dir.path());

    assert_eq!(store.load(ACCOUNT_KEY_ID).unwrap(), None);
    store
        .store(ACCOUNT_KEY_ID, b"account-key-32-bytes-xxxxxxxxxxxx")
        .unwrap();
    assert_eq!(
        store.load(ACCOUNT_KEY_ID).unwrap(),
        Some(b"account-key-32-bytes-xxxxxxxxxxxx".to_vec())
    );

    store.delete(ACCOUNT_KEY_ID).unwrap();
    assert_eq!(store.load(ACCOUNT_KEY_ID).unwrap(), None);
}

#[test]
fn file_store_rejects_path_traversal_in_id() {
    let dir = TempDir::new();
    let store = FileSecureStore::new(dir.path());
    // 恶意 id 不应逃逸出目录
    store.store("../../etc/passwd", b"x").unwrap();
    let escaped = dir.path().parent().unwrap().join("etc/passwd.bin");
    assert!(!escaped.exists(), "不得写出到目录之外");
}

#[test]
fn store_works_as_trait_object() {
    let store: Box<dyn SecureStore> = Box::new(MemorySecureStore::new());
    store.store(ACCOUNT_KEY_ID, b"k").unwrap();
    assert!(store.load(ACCOUNT_KEY_ID).unwrap().is_some());
}

#[test]
fn account_key_lifecycle_simulation() {
    // 模拟：生成 AccountKey → 存入安全存储 → 读取 → 用后删除
    let store = MemorySecureStore::new();
    let account_key = CryptoRng::bytes(32);
    store.store(ACCOUNT_KEY_ID, &account_key).unwrap();

    let loaded = store.load(ACCOUNT_KEY_ID).unwrap().expect("应能读回");
    assert_eq!(loaded.len(), 32, "AccountKey 必须为 256-bit");
    assert_eq!(loaded, account_key);

    store.delete(ACCOUNT_KEY_ID).unwrap();
    assert!(store.load(ACCOUNT_KEY_ID).unwrap().is_none());
}
