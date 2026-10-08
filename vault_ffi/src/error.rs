//! FFI 错误封装与 panic 守卫。
//!
//! **核心不变量**：任何从 `extern "C"` 返回的路径都不得携带 Rust panic
//! （UB 分类 14 — unwinding across FFI），因此所有入口统一经 [`guard`] 包裹。

use std::cell::RefCell;
use std::ffi::CString;
use std::panic::{catch_unwind, AssertUnwindSafe};

use vault_store::VaultError;

thread_local! {
    /// 最近一次错误的 JSON（线程局部：避免多线程场景下互相覆盖）。
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// FFI 层错误（最终序列化为 `{"code":..,"message":..}`）。
#[derive(Debug, Clone)]
pub struct FfiError {
    /// 机器可读错误码。
    pub code: &'static str,
    /// 人类可读消息。
    pub message: String,
}

impl FfiError {
    /// 参数类错误。
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            code: "BAD_REQUEST",
            message: message.into(),
        }
    }

    /// 内部错误（含被拦截的 panic）。
    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            code: "INTERNAL",
            message: message.into(),
        }
    }

    /// 由数据层错误映射。
    pub fn from_vault(err: VaultError) -> Self {
        match err {
            VaultError::InvalidInput(m) => Self::bad_request(m),
            VaultError::Locked { remaining_secs } => Self {
                code: "TOO_MANY_ATTEMPTS",
                message: format!("连续输错次数过多，请在 {remaining_secs} 秒后重试"),
            },
            VaultError::NotInitialized => Self::bad_request("保险库尚未初始化"),
            VaultError::AccountNotFound(id) => Self {
                code: "NOT_FOUND",
                message: format!("账号不存在: {id}"),
            },
            VaultError::SecretNotFound(t) => Self {
                code: "NOT_FOUND",
                message: format!("字段不存在: {t}"),
            },
            other => Self::internal(other.to_string()),
        }
    }

    /// 序列化为 JSON 字符串。
    fn to_json(&self) -> String {
        serde_json::json!({ "code": self.code, "message": self.message }).to_string()
    }
}

/// 记录错误到线程局部槽位（供 `fuxipass_last_error` 读取）。
pub fn store_error(err: &FfiError) {
    let Ok(json) = CString::new(err.to_json()) else {
        return;
    };
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some(json);
    });
}

/// 克隆当前线程最近一次错误（`None` 表示无错误）。
pub fn clone_last_error() -> Option<CString> {
    LAST_ERROR.with(|slot| slot.borrow().as_ref().cloned())
}

/// 执行闭包并拦截 panic。
///
/// 若闭包 panic，返回统一的内部错误而**不跨 FFI 边界展开**（UB 分类 14）。
/// `AssertUnwindSafe` 是必要的：闭包会捕获裸指针，而 `UnwindSafe` 无法为裸指针自动成立；
/// 由于每个闭包都是「一次性、不共享可变状态」的调用，断言成立。
pub fn guard<T>(f: impl FnOnce() -> Result<T, FfiError>) -> Result<T, FfiError> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(_) => Err(FfiError::internal("内部错误（已拦截，未跨 FFI 展开）")),
    }
}
