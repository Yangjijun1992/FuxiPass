//! 平台安全存储抽象（T1.4）。
//!
//! # 设计
//!
//! OS 级安全存储（Android Keystore / iOS Keychain / PC 文件）差异很大，
//! 因此抽象为 [`SecureStore`] trait：
//! - **移动端**：由 Dart 侧经 `MethodChannel` 调用原生实现（见 `docs/07` §4），
//!   本 crate 通过 [`adaptor::CallbackSecureStore`] 转接；
//! - **PC 原型**：用 [`FileSecureStore`]（**无硬件保护**，仅在无安全隔区时兜底）；
//! - **测试**：用 [`MemorySecureStore`]。
//!
//! # 安全契约
//!
//! `SecureStore` 只存**密钥材料**（如 AccountKey），**绝不**存主密码、
//! 数据密文或任何可解密数据的凭据。取出的值必须由调用方尽快使用并丢弃。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// 平台存储错误。
#[derive(Debug, Clone, thiserror::Error)]
pub enum PlatformError {
    /// 底层 IO 失败。
    #[error("platform storage io error: {0}")]
    Io(String),
    /// 平台不支持该能力。
    #[error("platform capability unavailable: {0}")]
    Unavailable(String),
    /// 存储项不存在。
    #[error("secret not found: {0}")]
    NotFound(String),
}

/// AccountKey 在安全存储中的标准条目名。
pub const ACCOUNT_KEY_ID: &str = "fuxipass.account_key";

/// 平台安全存储抽象。
pub trait SecureStore: Send + Sync {
    /// 写入/覆盖密钥材料。
    fn store(&self, id: &str, secret: &[u8]) -> Result<(), PlatformError>;
    /// 读取密钥材料；不存在返回 `Ok(None)`。
    fn load(&self, id: &str) -> Result<Option<Vec<u8>>, PlatformError>;
    /// 删除密钥材料（不存在时静默成功）。
    fn delete(&self, id: &str) -> Result<(), PlatformError>;
}

/// 内存实现（测试与演示用；进程退出即消失）。
#[derive(Default)]
pub struct MemorySecureStore {
    inner: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemorySecureStore {
    /// 新建空存储。
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<u8>>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl SecureStore for MemorySecureStore {
    fn store(&self, id: &str, secret: &[u8]) -> Result<(), PlatformError> {
        self.lock().insert(id.to_owned(), secret.to_vec());
        Ok(())
    }

    fn load(&self, id: &str) -> Result<Option<Vec<u8>>, PlatformError> {
        Ok(self.lock().get(id).cloned())
    }

    fn delete(&self, id: &str) -> Result<(), PlatformError> {
        self.lock().remove(id);
        Ok(())
    }
}

/// 文件实现（**仅 PC 原型兜底**）。
///
/// ⚠️ **不提供硬件级保护**：密钥以文件形式落在磁盘上，任何能读取该文件的进程
/// 都能取得 AccountKey。移动端必须使用 Keystore/Keychain（见 `docs/07` §4）。
pub struct FileSecureStore {
    dir: PathBuf,
}

impl FileSecureStore {
    /// 指定存放目录（调用方应确保目录权限为 0700）。
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path_of(&self, id: &str) -> PathBuf {
        // 仅允许安全字符，避免路径穿越
        let safe: String = id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.dir.join(format!("{safe}.bin"))
    }
}

impl SecureStore for FileSecureStore {
    fn store(&self, id: &str, secret: &[u8]) -> Result<(), PlatformError> {
        std::fs::create_dir_all(&self.dir).map_err(|e| PlatformError::Io(e.to_string()))?;
        std::fs::write(self.path_of(id), secret).map_err(|e| PlatformError::Io(e.to_string()))
    }

    fn load(&self, id: &str) -> Result<Option<Vec<u8>>, PlatformError> {
        let path = self.path_of(id);
        if !path.exists() {
            return Ok(None);
        }
        std::fs::read(path)
            .map(Some)
            .map_err(|e| PlatformError::Io(e.to_string()))
    }

    fn delete(&self, id: &str) -> Result<(), PlatformError> {
        let path = self.path_of(id);
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| PlatformError::Io(e.to_string()))?;
        }
        Ok(())
    }
}

impl FileSecureStore {
    /// 存储目录（供调用方设置权限）。
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// 原生回调桥接：由移动端（Dart → Kotlin/Swift）提供实现。
///
/// 移动端在启动时注册四个函数指针（存/取/删/可用性查询），
/// Rust 侧通过本结构把 [`SecureStore`] 的调用转发给真实平台 API。
pub mod adaptor {
    use super::{PlatformError, SecureStore};

    /// 原生实现签名：`(id_ptr, id_len, secret_ptr, secret_len) -> i32`。
    ///
    /// 约定：返回 `0` 成功；`1` 不存在；负数表示错误。缓冲区由调用方保证有效。
    pub type NativeStoreFn = extern "C" fn(
        id_ptr: *const u8,
        id_len: usize,
        secret_ptr: *const u8,
        secret_len: usize,
    ) -> i32;

    /// 原生读取函数签名：把结果写入调用方缓冲，返回实际长度（负数为错误）。
    pub type NativeLoadFn =
        extern "C" fn(id_ptr: *const u8, id_len: usize, out_ptr: *mut u8, out_cap: usize) -> isize;

    /// 桥接结构：持有原生函数指针。
    pub struct CallbackSecureStore {
        store_fn: NativeStoreFn,
        load_fn: NativeLoadFn,
        delete_fn: NativeStoreFn,
        max_secret_len: usize,
    }

    impl CallbackSecureStore {
        /// 由原生层注册函数指针后构造。
        pub const fn new(
            store_fn: NativeStoreFn,
            load_fn: NativeLoadFn,
            delete_fn: NativeStoreFn,
            max_secret_len: usize,
        ) -> Self {
            Self {
                store_fn,
                load_fn,
                delete_fn,
                max_secret_len,
            }
        }
    }

    impl SecureStore for CallbackSecureStore {
        fn store(&self, id: &str, secret: &[u8]) -> Result<(), PlatformError> {
            let code = (self.store_fn)(id.as_ptr(), id.len(), secret.as_ptr(), secret.len());
            match code {
                0 => Ok(()),
                n if n < 0 => Err(PlatformError::Io(format!("native store error {n}"))),
                _ => Err(PlatformError::Unavailable(
                    "native store rejected".to_owned(),
                )),
            }
        }

        fn load(&self, id: &str) -> Result<Option<Vec<u8>>, PlatformError> {
            let mut buf = vec![0_u8; self.max_secret_len];
            let len = (self.load_fn)(id.as_ptr(), id.len(), buf.as_mut_ptr(), buf.len());
            match len {
                0 => Ok(None),
                n if n < 0 => Err(PlatformError::Io(format!("native load error {n}"))),
                n => {
                    let n = usize::try_from(n)
                        .map_err(|_| PlatformError::Io("bad length".to_owned()))?;
                    if n > buf.len() {
                        return Err(PlatformError::Io(
                            "native returned oversized secret".to_owned(),
                        ));
                    }
                    buf.truncate(n);
                    Ok(Some(buf))
                }
            }
        }

        fn delete(&self, id: &str) -> Result<(), PlatformError> {
            let code = (self.delete_fn)(id.as_ptr(), id.len(), std::ptr::null(), 0);
            match code {
                0 => Ok(()),
                n => Err(PlatformError::Io(format!("native delete error {n}"))),
            }
        }
    }
}
