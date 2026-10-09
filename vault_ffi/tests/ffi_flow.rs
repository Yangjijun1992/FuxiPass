// 集成测试为**纯测试代码**，允许 unwrap/expect/panic（生产代码 src/ 仍全局 deny）。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! FFI 端到端流程测试（需数据库，Miri 下跳过）。
//!
//! 覆盖：解锁 → 列表 → 新建 → 详情 → 二次验证揭示 → 更新 → 删除 → 释放句柄，
//! 以及错误主密码与缺失账号的失败路径。

#![cfg_attr(miri, allow(dead_code))]

use std::ffi::{c_char, CStr, CString};
use std::path::{Path, PathBuf};
use std::ptr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use security_core::cipher::CryptoRng;
use vault_ffi::{
    fuxipass_create_account, fuxipass_delete_account, fuxipass_get_account, fuxipass_last_error,
    fuxipass_list_accounts, fuxipass_lock, fuxipass_lock_status, fuxipass_reveal_secret,
    fuxipass_string_free, fuxipass_unlock, fuxipass_unlock_second_factor, fuxipass_update_account,
};
use vault_store::{initialize, AccountInput, Importance};

/// 每个用例独立跳过 Miri（数据库为 C 实现，Miri 无法解释）。
macro_rules! db_test {
    ($name:ident, $body:block) => {
        #[test]
        fn $name() {
            if cfg!(miri) {
                eprintln!("跳过：数据库测试不适用于 Miri");
                return;
            }
            $body
        }
    };
}

const MASTER: &str = "ffi-master-password-123";

struct TempVault {
    path: PathBuf,
}

impl TempVault {
    fn new() -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "fuxipass_ffi_{}.db",
            URL_SAFE_NO_PAD.encode(CryptoRng::bytes(10))
        ));
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempVault {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut p = self.path.clone().into_os_string();
            p.push(suffix);
            let _ = std::fs::remove_file(PathBuf::from(p));
        }
    }
}

fn sample_json() -> String {
    let input = AccountInput {
        app_name: "中国建设银行".to_owned(),
        url: Some("https://ebank.ccb.com".to_owned()),
        username: Some("zhangsan_123".to_owned()),
        notes: Some("密保答案：蓝色".to_owned()),
        importance: Importance::Finance,
        login_password: Some("LoginPw!234".to_owned()),
        secondary_password: Some("888444".to_owned()),
        payment_password: None,
        api_key: None,
    };
    serde_json::to_string(&input).unwrap()
}

/// 取回并释放 FFI 返回的字符串。
fn take(ptr: *mut c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: 指针由本库分配、NUL 结尾，读取后立即释放一次。
    let s = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(str::to_owned);
    // SAFETY: [分类 12] ptr 由本库分配且此处仅释放一次。
    unsafe { fuxipass_string_free(ptr) };
    s
}

fn last_error() -> Option<String> {
    take(fuxipass_last_error())
}

db_test!(unlock_list_create_reveal_update_delete_flow, {
    let tv = TempVault::new();
    let _ = initialize(tv.path(), MASTER).unwrap();

    let path = CString::new(tv.path().to_str().unwrap()).unwrap();
    let pw = CString::new(MASTER).unwrap();

    // 解锁
    // SAFETY: 两个字符串均由 CString 持有且在本作用域内存活。
    let handle = unsafe { fuxipass_unlock(path.as_ptr(), pw.as_ptr()) };
    assert!(!handle.is_null(), "解锁失败: {:?}", last_error());

    // 初始为空
    // SAFETY: handle 来自上面的 unlock，尚未释放。
    let empty = take(unsafe { fuxipass_list_accounts(handle) }).unwrap();
    assert_eq!(empty, "[]");

    // 二次验证（FDEK）：样例含高敏感字段（二级密码），必须先解包 FDEK
    // SAFETY: handle 有效；pw 由 CString 持有。
    let code = unsafe { fuxipass_unlock_second_factor(handle, pw.as_ptr()) };
    assert_eq!(code, 0, "二次验证应成功: {:?}", last_error());

    // 新建
    let input = CString::new(sample_json()).unwrap();
    // SAFETY: handle 有效；input 由 CString 持有。
    let code = unsafe { fuxipass_create_account(handle, input.as_ptr()) };
    assert_eq!(code, 0, "新建失败: {:?}", last_error());

    // 列表应含 1 条
    // SAFETY: handle 有效。
    let listed = take(unsafe { fuxipass_list_accounts(handle) }).unwrap();
    assert!(listed.contains("中国建设银行"), "列表: {listed}");

    // 取 id
    let accounts: Vec<serde_json::Value> = serde_json::from_str(&listed).unwrap();
    let id = accounts[0]["id"].as_str().unwrap().to_owned();
    let id_c = CString::new(id.clone()).unwrap();

    // 详情
    // SAFETY: handle 有效；id_c 由 CString 持有。
    let detail = take(unsafe { fuxipass_get_account(handle, id_c.as_ptr()) }).unwrap();
    assert!(detail.contains("密保答案"), "详情: {detail}");

    // 二次验证：错误主密码必须失败
    let field = CString::new("secondary_password").unwrap();
    let wrong = CString::new("definitely-wrong-pw").unwrap();
    // SAFETY: handle 有效；三个 CString 均存活。
    let denied =
        unsafe { fuxipass_reveal_secret(handle, id_c.as_ptr(), field.as_ptr(), wrong.as_ptr()) };
    assert!(denied.is_null(), "错误主密码不得揭示明文");
    let err = last_error().unwrap();
    assert!(
        err.contains("UNAUTHORIZED") || err.contains("主密码"),
        "错误: {err}"
    );

    // 二次验证：正确主密码
    // SAFETY: handle 有效；参数均为存活的 CString。
    let revealed =
        unsafe { fuxipass_reveal_secret(handle, id_c.as_ptr(), field.as_ptr(), pw.as_ptr()) };
    let json = take(revealed).expect("正确主密码应揭示成功");
    assert!(json.contains("888444"), "揭示结果: {json}");

    // 更新
    let mut updated: serde_json::Value = serde_json::from_str(&sample_json()).unwrap();
    updated["app_name"] = serde_json::json!("建设银行(改)");
    let updated_c = CString::new(updated.to_string()).unwrap();
    // SAFETY: handle 有效；参数为存活的 CString。
    let code = unsafe { fuxipass_update_account(handle, id_c.as_ptr(), updated_c.as_ptr()) };
    assert_eq!(code, 0, "更新失败: {:?}", last_error());

    // 删除
    // SAFETY: handle 有效；id_c 存活。
    let code = unsafe { fuxipass_delete_account(handle, id_c.as_ptr()) };
    assert_eq!(code, 0, "删除失败: {:?}", last_error());
    // SAFETY: handle 来自上面的 unlock 且尚未释放。
    let after_delete = take(unsafe { fuxipass_list_accounts(handle) }).unwrap();
    assert_eq!(after_delete, "[]");

    // 释放句柄
    // SAFETY: handle 来自 unlock 且此前从未释放，此处一次性释放。
    unsafe { fuxipass_lock(handle) };
});

db_test!(unlock_with_wrong_password_fails, {
    let tv = TempVault::new();
    let _ = initialize(tv.path(), MASTER).unwrap();
    let path = CString::new(tv.path().to_str().unwrap()).unwrap();
    let wrong = CString::new("wrong-master-pw").unwrap();
    // SAFETY: 两个 CString 均存活。
    let handle = unsafe { fuxipass_unlock(path.as_ptr(), wrong.as_ptr()) };
    assert!(handle.is_null(), "错误主密码必须失败");
    assert!(last_error().is_some());
});

db_test!(operations_on_missing_account_report_not_found, {
    let tv = TempVault::new();
    let _ = initialize(tv.path(), MASTER).unwrap();
    let path = CString::new(tv.path().to_str().unwrap()).unwrap();
    let pw = CString::new(MASTER).unwrap();
    // SAFETY: 参数均存活。
    let handle = unsafe { fuxipass_unlock(path.as_ptr(), pw.as_ptr()) };
    assert!(!handle.is_null());

    let missing = CString::new("no-such-id").unwrap();
    // SAFETY: handle 有效；missing 存活。
    let detail = unsafe { fuxipass_get_account(handle, missing.as_ptr()) };
    assert!(detail.is_null());
    let err = last_error().unwrap();
    assert!(err.contains("NOT_FOUND"), "错误: {err}");

    // SAFETY: handle 尚未释放。
    unsafe { fuxipass_lock(handle) };
});

db_test!(lock_status_reports_unlocked_flow_state, {
    let tv = TempVault::new();
    let _ = initialize(tv.path(), MASTER).unwrap();
    let path = CString::new(tv.path().to_str().unwrap()).unwrap();
    // SAFETY: path 存活。
    let json = take(unsafe { fuxipass_lock_status(path.as_ptr()) }).unwrap();
    let status: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(status["locked"], false);
    assert_eq!(status["failed_attempts"], 0);
});

db_test!(null_handle_operations_return_error_not_panic, {
    // 传入空句柄的库操作必须安全失败
    // SAFETY: 空句柄是契约允许的输入。
    let value = unsafe { fuxipass_list_accounts(ptr::null_mut()) };
    assert!(value.is_null());
    assert!(last_error().is_some());
});
