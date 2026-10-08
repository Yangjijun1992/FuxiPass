//! FFI 边界安全测试。
//!
//! **全部用例均不触碰数据库**，因此可在 Miri 下运行（验证指针/内存正确性）。
//! 覆盖：空指针、非法 UTF-8、字符串所有权配对、panic 不跨边界。

use std::ffi::{CStr, CString};
use std::ptr;

use vault_ffi::convert::{free_c_string, to_c_string};
use vault_ffi::{
    fuxipass_lock, fuxipass_lock_status, fuxipass_string_free, fuxipass_unlock,
};
use vault_ffi::error::clone_last_error;

/// 读取 C 字符串并释放（测试辅助，配对正确）。
fn take(ptr: *mut std::ffi::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: 指针由本库分配且以 NUL 结尾；此处读取后立即释放一次。
    let s = unsafe { CStr::from_ptr(ptr) }.to_str().ok().map(str::to_owned);
    unsafe { fuxipass_string_free(ptr) };
    s
}

#[test]
fn string_roundtrip_pairs_alloc_and_free() {
    let original = String::from("测试-áé~!@#$%^&*()");
    let ptr = to_c_string(original.clone());
    assert!(!ptr.is_null());
    // SAFETY: 指针刚由 to_c_string 分配，尚未释放。
    let back = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_owned();
    // SAFETY: 与上面的分配一一配对，仅释放一次。
    unsafe { free_c_string(ptr) };
    assert_eq!(back, original);
}

#[test]
fn free_null_string_is_noop() {
    // SAFETY: 空指针按契约是允许的无操作输入。
    unsafe { free_c_string(ptr::null_mut()) };
    // SAFETY: 同上（对外导出函数路径）。
    unsafe { fuxipass_string_free(ptr::null_mut()) };
}

#[test]
fn unlock_with_null_path_is_rejected_without_panic() {
    let pw = CString::new("whatever").unwrap();
    // SAFETY: 传入空指针是契约允许的（函数内部先检查）。
    let handle = unsafe { fuxipass_unlock(ptr::null(), pw.as_ptr()) };
    assert!(handle.is_null(), "空路径必须返回 NULL");
    let err = clone_last_error();
    let msg = err.map(|c| c.into_string().unwrap_or_default());
    assert!(
        msg.as_deref().is_some_and(|m| m.contains("db_path")),
        "错误信息应指明参数名，实际: {msg:?}"
    );
}

#[test]
fn unlock_with_null_password_is_rejected_without_panic() {
    let path = CString::new("/tmp/fuxipass-ffi-safety.db").unwrap();
    // SAFETY: 传入空密码指针是契约允许的。
    let handle = unsafe { fuxipass_unlock(path.as_ptr(), ptr::null()) };
    assert!(handle.is_null());
}

#[test]
fn unlock_with_invalid_utf8_is_rejected_without_panic() {
    // 0xFF 不是合法 UTF-8 起始字节
    let bad = [0xFF_u8, 0xFE, 0x00];
    let pw = CString::new("pw").unwrap();
    // SAFETY: 指针以 NUL 结尾且可读；内容非法 UTF-8 由函数内部校验。
    let handle = unsafe { fuxipass_unlock(bad.as_ptr().cast(), pw.as_ptr()) };
    assert!(handle.is_null());
}

#[test]
fn lock_with_null_handle_is_noop() {
    // SAFETY: 空句柄按契约是允许的无操作输入。
    unsafe { fuxipass_lock(ptr::null_mut()) };
}

#[test]
fn lock_status_with_null_path_is_rejected() {
    // SAFETY: 空指针按契约允许。
    let value = unsafe { fuxipass_lock_status(ptr::null()) };
    assert!(value.is_null());
}

#[test]
fn taking_reported_error_twice_is_safe() {
    // 触发一次错误
    // SAFETY: 空指针输入。
    let _ = unsafe { fuxipass_lock_status(ptr::null()) };
    let first = take_error();
    let second = take_error();
    assert!(first.is_some() && second.is_some(), "每次调用都应返回独立副本");
}

/// 读取并释放 `fuxipass_last_error` 返回的指针。
fn take_error() -> Option<String> {
    take(vault_ffi::fuxipass_last_error())
}
