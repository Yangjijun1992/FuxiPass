//! 跨 FFI 边界的数据转换（指针 ↔ Rust 值）。
//!
//! 本模块集中全部「悬垂指针 / 非法值 / 内存所有权」相关的 `unsafe`，
//! 每个函数都写明调用方契约（UB 分类 3、5、8、12）。

use std::ffi::{c_char, CStr, CString};
use std::ptr;

use crate::error::FfiError;
use crate::FuxiHandle;

/// 把 Dart 传入的 C 字符串转为 `String`。
///
/// # Safety
///
/// [分类 8 — FFI 边界] `ptr` 必须为 `null`，或指向一个 **以 NUL 结尾**、
/// 且在本次调用期间保持有效且不被写入的字符串（由 Dart 侧 `toNativeUtf8()`
/// 保证，其内存在本次调用结束前不会释放）。函数内先做空指针检查，
/// 因此传入 `null` 是安全的（返回错误而非 UB）。
pub unsafe fn cstr_to_string(ptr: *const c_char, name: &str) -> Result<String, FfiError> {
    if ptr.is_null() {
        return Err(FfiError::bad_request(format!("{name} 为空指针")));
    }
    // SAFETY: [分类 8] 由调用方契约保证 `ptr` 非空且以 NUL 结尾；
    // `CStr::from_ptr` 只读取到首个 NUL 为止，不越界，返回值不逃逸本函数。
    let c = unsafe { CStr::from_ptr(ptr) };
    c.to_str()
        .map(str::to_owned)
        .map_err(|e| FfiError::bad_request(format!("{name} 不是合法 UTF-8: {e}")))
}

/// 把句柄转为 `&Vault`（只读借用以外的可变性由调用方保证为独占）。
///
/// # Safety
///
/// [分类 3/5 — 悬垂指针/非法值] `handle` 必须是 `fuxipass_unlock` 返回、
/// 且**尚未**经 `fuxipass_lock` 释放的非空指针；并且在本调用期间，
/// 调用方不得并发释放该句柄，也不得同时传入同一句柄进行可变操作
/// （Dart 侧按「单句柄单线程使用」契约执行，见设计文档 §2）。
/// 函数内先做空指针检查，因此传入 `null` 是安全的。
pub unsafe fn handle_ref<'a>(handle: *mut FuxiHandle) -> Result<&'a mut FuxiHandle, FfiError> {
    if handle.is_null() {
        return Err(FfiError::bad_request("句柄为空指针"));
    }
    // SAFETY: [分类 3] 由调用方契约保证指针有效且未释放；返回的可变引用
    // 生命周期被限制在调用方的作用域内，且同一时刻只有一个借用存在。
    Ok(unsafe { &mut *handle })
}

/// 把 Rust 字符串转为由本库分配、调用方负责释放的 C 字符串指针。
///
/// 返回 `null` 表示字符串中含有内部 NUL（无法表示为 C 字符串）。
/// 调用方**必须**用 [`crate::fuxipass_string_free`] 释放，否则泄漏（分类 12）。
pub fn to_c_string(value: String) -> *mut c_char {
    match CString::new(value) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// 释放由 [`to_c_string`] / `CString::into_raw` 产生的指针。
///
/// # Safety
///
/// [分类 12 — 重复释放] `ptr` 必须为 `null`，或为**本库**通过
/// `CString::into_raw` 产生且**从未被释放过**的指针。向本函数传入
/// 非本库分配的内存、或对同一指针调用两次，均为未定义行为。
pub unsafe fn free_c_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: [分类 12] 由调用方契约保证该指针源自 CString::into_raw 且仅释放一次；
    // from_raw 重新取得所有权后立即 drop，恰释放一次。
    drop(unsafe { CString::from_raw(ptr) });
}
