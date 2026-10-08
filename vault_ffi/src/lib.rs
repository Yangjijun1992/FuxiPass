//! # vault_ffi —— 移动端 FFI 层（C ABI）
//!
//! 供 Flutter（`dart:ffi`）/ Android（JNI）/ iOS（静态库）调用。
//! 契约与平台映射见 `docs/07-移动端集成设计.md`。
//!
//! ## 内存与安全约定
//! 1. **句柄**：`fuxipass_unlock` 返回不透明 `*mut FuxiHandle`，**必须**用
//!    `fuxipass_lock` 释放；释放后再次使用是 UB。
//! 2. **字符串**：所有返回的 `*mut c_char` 由本库分配，**必须**用
//!    `fuxipass_string_free` 释放。
//! 3. **panic**：所有入口经 [`error::guard`] 包裹，绝不跨 FFI 边界展开（UB 分类 14）。
//! 4. **线程**：一个句柄只应在一个线程内使用；错误信息存于线程局部。
//!
//! ## 返回值约定
//! - 返回指针的函数：失败返回 `NULL`，详情读 `fuxipass_last_error()`。
//! - 返回 `c_int` 的函数：`0` 表示成功，负值表示失败码。

pub mod convert;
pub mod error;

use std::ffi::{c_char, c_int};
use std::path::Path;
use std::ptr;

use vault_store::FieldType;

use crate::convert::{cstr_to_string, free_c_string, handle_ref, to_c_string};
use crate::error::{clone_last_error, guard, store_error, FfiError};

/// 不透明句柄：内部持有已解锁的保险库与其数据库路径。
pub struct FuxiHandle {
    /// 数据库路径（供二次验证等独立操作使用）。
    db_path: std::path::PathBuf,
    /// 已解锁的保险库。
    vault: vault_store::Vault,
}

/// 解锁保险库。
///
/// 返回句柄；失败返回 `NULL`（错误见 `fuxipass_last_error`）。
///
/// # Safety
///
/// [分类 8] `db_path` 与 `master_password` 必须为合法的 NUL 结尾 C 字符串
/// 或 `NULL`（由 Dart 侧 `toNativeUtf8()` 保证生命周期覆盖本次调用）。
#[no_mangle]
pub unsafe extern "C" fn fuxipass_unlock(
    db_path: *const c_char,
    master_password: *const c_char,
) -> *mut FuxiHandle {
    let result = guard(|| {
        // SAFETY: [分类 8 — FFI 边界] 本函数 `# Safety` 契约保证两个入参均为
        // 合法的 NUL 结尾 C 字符串（或 NULL，函数内会检查），且在本次调用期间有效。
        let (path, password) = unsafe {
            (
                cstr_to_string(db_path, "db_path")?,
                cstr_to_string(master_password, "master_password")?,
            )
        };
        let vault =
            vault_store::unlock(Path::new(&path), &password).map_err(FfiError::from_vault)?;
        Ok(Box::into_raw(Box::new(FuxiHandle {
            db_path: Path::new(&path).to_path_buf(),
            vault,
        })))
    });
    match result {
        Ok(handle) => handle,
        Err(err) => {
            store_error(&err);
            ptr::null_mut()
        }
    }
}

/// 释放句柄（内部 `Vault` 被 drop，密钥经 zeroize 擦除）。
///
/// # Safety
///
/// [分类 3/12] `handle` 必须为 `NULL`（无操作）或 `fuxipass_unlock` 返回且
/// **尚未释放**的指针；对同一句柄调用两次是 UB。
#[no_mangle]
pub unsafe extern "C" fn fuxipass_lock(handle: *mut FuxiHandle) {
    if handle.is_null() {
        return;
    }
    // SAFETY: [分类 12] 由调用方契约保证该指针源自 Box::into_raw 且仅释放一次。
    drop(unsafe { Box::from_raw(handle) });
}

/// 列出账号摘要（JSON 数组）；失败返回 `NULL`。
///
/// # Safety
///
/// [分类 3] `handle` 必须为有效且未释放的句柄（见 [`handle_ref`] 契约）。
#[no_mangle]
pub unsafe extern "C" fn fuxipass_list_accounts(handle: *mut FuxiHandle) -> *mut c_char {
    let result = guard(|| {
        // SAFETY: [分类 3 — 悬垂指针] 本函数 `# Safety` 契约保证 handle 有效且未释放；
        // 返回的借用不逃逸本次调用。
        let state = unsafe { handle_ref(handle) }?;
        let accounts = state.vault.list_accounts().map_err(FfiError::from_vault)?;
        let json =
            serde_json::to_string(&accounts).map_err(|e| FfiError::internal(e.to_string()))?;
        Ok(to_c_string(json))
    });
    match result {
        Ok(value) => value,
        Err(err) => {
            store_error(&err);
            ptr::null_mut()
        }
    }
}

/// 读取账号详情（JSON）；失败返回 `NULL`。
///
/// # Safety
///
/// [分类 3/8] `handle` 有效且未释放；`account_id` 为合法 C 字符串或 `NULL`。
#[no_mangle]
pub unsafe extern "C" fn fuxipass_get_account(
    handle: *mut FuxiHandle,
    account_id: *const c_char,
) -> *mut c_char {
    let result = guard(|| {
        // SAFETY: [分类 3/8] 本函数 `# Safety` 契约保证 handle 有效且未释放、
        // account_id 为合法 C 字符串或 NULL。
        let (state, id) = unsafe {
            (
                handle_ref(handle)?,
                cstr_to_string(account_id, "account_id")?,
            )
        };
        let detail = state.vault.get_account(&id).map_err(FfiError::from_vault)?;
        let json = serde_json::to_string(&detail).map_err(|e| FfiError::internal(e.to_string()))?;
        Ok(to_c_string(json))
    });
    match result {
        Ok(value) => value,
        Err(err) => {
            store_error(&err);
            ptr::null_mut()
        }
    }
}

/// 新建账号（`input_json` 为 `AccountInput` JSON）；成功返回 `0`。
///
/// # Safety
///
/// [分类 3/8] `handle` 有效且未释放；`input_json` 为合法 C 字符串或 `NULL`。
#[no_mangle]
pub unsafe extern "C" fn fuxipass_create_account(
    handle: *mut FuxiHandle,
    input_json: *const c_char,
) -> c_int {
    let result = guard(|| {
        // SAFETY: [分类 3/8] 本函数 `# Safety` 契约保证 handle 有效且未释放、
        // input_json 为合法 C 字符串或 NULL。
        let (state, raw) = unsafe {
            (
                handle_ref(handle)?,
                cstr_to_string(input_json, "input_json")?,
            )
        };
        let input: vault_store::AccountInput = serde_json::from_str(&raw)
            .map_err(|e| FfiError::bad_request(format!("input_json 解析失败: {e}")))?;
        state
            .vault
            .create_account(&input)
            .map_err(FfiError::from_vault)?;
        Ok(0)
    });
    match result {
        Ok(code) => code,
        Err(err) => {
            store_error(&err);
            -1
        }
    }
}

/// 更新账号；成功返回 `0`。
///
/// # Safety
///
/// [分类 3/8] 同 [`fuxipass_create_account`]，额外要求 `account_id` 合法。
#[no_mangle]
pub unsafe extern "C" fn fuxipass_update_account(
    handle: *mut FuxiHandle,
    account_id: *const c_char,
    input_json: *const c_char,
) -> c_int {
    let result = guard(|| {
        // SAFETY: [分类 3/8] 本函数 `# Safety` 契约保证 handle 有效且未释放、
        // 两个字符串参数合法或为 NULL。
        let (state, id, raw) = unsafe {
            (
                handle_ref(handle)?,
                cstr_to_string(account_id, "account_id")?,
                cstr_to_string(input_json, "input_json")?,
            )
        };
        let input: vault_store::AccountInput = serde_json::from_str(&raw)
            .map_err(|e| FfiError::bad_request(format!("input_json 解析失败: {e}")))?;
        state
            .vault
            .update_account(&id, &input)
            .map_err(FfiError::from_vault)?;
        Ok(0)
    });
    match result {
        Ok(code) => code,
        Err(err) => {
            store_error(&err);
            -1
        }
    }
}

/// 删除账号；成功返回 `0`。
///
/// # Safety
///
/// [分类 3/8] `handle` 有效且未释放；`account_id` 为合法 C 字符串或 `NULL`。
#[no_mangle]
pub unsafe extern "C" fn fuxipass_delete_account(
    handle: *mut FuxiHandle,
    account_id: *const c_char,
) -> c_int {
    let result = guard(|| {
        // SAFETY: [分类 3/8] 本函数 `# Safety` 契约保证 handle 有效且未释放、
        // account_id 合法或为 NULL。
        let (state, id) = unsafe {
            (
                handle_ref(handle)?,
                cstr_to_string(account_id, "account_id")?,
            )
        };
        state
            .vault
            .delete_account(&id)
            .map_err(FfiError::from_vault)?;
        Ok(0)
    });
    match result {
        Ok(code) => code,
        Err(err) => {
            store_error(&err);
            -1
        }
    }
}

/// 揭示高敏感字段（需二次验证主密码）；返回 `{"value":".."}` JSON。
///
/// # Safety
///
/// [分类 3/8] `handle` 有效且未释放；三个字符串参数为合法 C 字符串或 `NULL`。
#[no_mangle]
pub unsafe extern "C" fn fuxipass_reveal_secret(
    handle: *mut FuxiHandle,
    account_id: *const c_char,
    field_type: *const c_char,
    master_password: *const c_char,
) -> *mut c_char {
    let result = guard(|| {
        // SAFETY: [分类 3/8] 本函数 `# Safety` 契约保证 handle 有效且未释放、
        // 三个字符串参数合法或为 NULL。
        let (state, id, field_raw, password) = unsafe {
            (
                handle_ref(handle)?,
                cstr_to_string(account_id, "account_id")?,
                cstr_to_string(field_type, "field_type")?,
                cstr_to_string(master_password, "master_password")?,
            )
        };
        let field = FieldType::parse(&field_raw)
            .ok_or_else(|| FfiError::bad_request(format!("未知字段类型: {field_raw}")))?;
        // 二次验证：与 Web 接口一致，必须先校验主密码再揭示（且同样受退避锁定约束）。
        let verified = vault_store::verify_master_password(&state.db_path, &password)
            .map_err(FfiError::from_vault)?;
        if !verified {
            return Err(FfiError {
                code: "UNAUTHORIZED",
                message: "二次验证失败：主密码不正确".to_owned(),
            });
        }
        let value = state
            .vault
            .reveal_secret(&id, field)
            .map_err(FfiError::from_vault)?;
        let json = serde_json::json!({ "value": value }).to_string();
        Ok(to_c_string(json))
    });
    match result {
        Ok(value) => value,
        Err(err) => {
            store_error(&err);
            ptr::null_mut()
        }
    }
}

/// 查询锁定状态（无需解锁）；返回 `LockStatus` JSON。
///
/// # Safety
///
/// [分类 8] `db_path` 为合法 C 字符串或 `NULL`。
#[no_mangle]
pub unsafe extern "C" fn fuxipass_lock_status(db_path: *const c_char) -> *mut c_char {
    let result = guard(|| {
        // SAFETY: [分类 8] 本函数 `# Safety` 契约保证 db_path 为合法
        // NUL 结尾 C 字符串或 NULL。
        let path = unsafe { cstr_to_string(db_path, "db_path") }?;
        let status = vault_store::lock_status(Path::new(&path)).map_err(FfiError::from_vault)?;
        let json = serde_json::to_string(&status).map_err(|e| FfiError::internal(e.to_string()))?;
        Ok(to_c_string(json))
    });
    match result {
        Ok(value) => value,
        Err(err) => {
            store_error(&err);
            ptr::null_mut()
        }
    }
}

/// 释放由本库返回的字符串。
///
/// # Safety
///
/// [分类 12] `value` 必须为 `NULL` 或由本库分配且未释放的指针（见 [`free_c_string`]）。
#[no_mangle]
pub unsafe extern "C" fn fuxipass_string_free(value: *mut c_char) {
    // SAFETY: [分类 12] 由调用方契约保证指针来源与一次性释放。
    unsafe { free_c_string(value) };
}

/// 读取本线程最近一次错误（JSON）；无错误返回 `NULL`。
///
/// 返回的指针同样需用 `fuxipass_string_free` 释放。
#[no_mangle]
pub extern "C" fn fuxipass_last_error() -> *mut c_char {
    match clone_last_error() {
        Some(c) => c.into_raw(),
        None => ptr::null_mut(),
    }
}
