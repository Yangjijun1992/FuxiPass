//! Android JNI 桥接：把 `vault_store` 暴露给 Kotlin/Java。
//!
//! 说明：
//! - 产物为 `libvault_jni.so`，由 Android 应用 `System.loadLibrary("vault_jni")` 加载。
//! - 本 crate 在 x86_64 宿主上也能编译（用于 CI 校验桥接代码），实际联调需 Android 端。
//! - 线程模型与网页端一致：同一时刻一个解锁会话，用全局 `Mutex<Option<Vault>>` 持有。
//!
//! 符号按 JNI 命名约定：`Java_<包名>_<类名>_<方法>`。这里假定 Java 侧为包
//! `com.fuxipass`、类 `VaultBridge`（Kotlin 侧需与之匹配，见下文类名注解）。

use std::sync::Mutex;

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jstring};
use jni::JNIEnv;
use serde_json::json;

use vault_store::Vault;

/// 当前已解锁的保险库（单会话）。
static VAULT: Mutex<Option<Vault>> = Mutex::new(None);

/// 在已锁定保险库上执行只读/写操作。
fn with_vault<R>(
    f: impl FnOnce(&Vault) -> Result<R, vault_store::VaultError>,
) -> Result<R, String> {
    let guard = VAULT.lock().map_err(|_| "内部锁损坏".to_owned())?;
    let vault = guard.as_ref().ok_or_else(|| "未解锁".to_owned())?;
    f(vault).map_err(|e| e.to_string())
}

/// 构造 `jstring`；失败返回空指针。
#[allow(clippy::not_unsafe_ptr_arg_deref)]
fn jstring(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s)
        .map(|j| j.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// 取 Java 字符串为 UTF-8。
fn jstr(env: &mut JNIEnv, s: JString) -> String {
    env.get_string(&s).map(|v| v.into()).unwrap_or_default()
}

fn json_error(env: &mut JNIEnv, msg: &str) -> jstring {
    jstring(env, &json!({ "ok": false, "error": msg }).to_string())
}

/// `initialize(path, master)` → `{"ok":true,"recovery_key":"..."}` 或 `{"ok":false,...}`。
#[no_mangle]
pub extern "system" fn Java_com_fuxipass_VaultBridge_initialize(
    mut env: JNIEnv,
    _: JClass,
    path: JString,
    master: JString,
) -> jstring {
    let r = vault_store::initialize(
        std::path::Path::new(&jstr(&mut env, path)),
        &jstr(&mut env, master),
    );
    match r {
        Ok(init) => jstring(
            &mut env,
            &json!({ "ok": true, "recovery_key": init.recovery_key_display }).to_string(),
        ),
        Err(e) => json_error(&mut env, &e.to_string()),
    }
}

/// `unlock(path, master)` → 1 成功 / 0 失败。
#[no_mangle]
pub extern "system" fn Java_com_fuxipass_VaultBridge_unlock(
    mut env: JNIEnv,
    _: JClass,
    path: JString,
    master: JString,
) -> jboolean {
    let r = vault_store::unlock(
        std::path::Path::new(&jstr(&mut env, path)),
        &jstr(&mut env, master),
    );
    match r {
        Ok(vault) => {
            *VAULT.lock().unwrap() = Some(vault);
            1
        }
        Err(_) => 0,
    }
}

/// `lock()` → 无返回值（清除当前会话，密钥经 zeroize 擦除）。
#[no_mangle]
pub extern "system" fn Java_com_fuxipass_VaultBridge_lock(_env: JNIEnv, _: JClass) {
    *VAULT.lock().unwrap() = None;
}

/// `list()` → `{"ok":true,"accounts":[{id,app_name,username,importance},...]}`。
#[no_mangle]
pub extern "system" fn Java_com_fuxipass_VaultBridge_list(mut env: JNIEnv, _: JClass) -> jstring {
    match with_vault(|v| v.list_accounts()) {
        Ok(items) => {
            let accounts: Vec<serde_json::Value> = items
                .iter()
                .map(|s| {
                    json!({
                        "id": s.id,
                        "app_name": s.app_name,
                        "username": s.username,
                        "importance": serde_json::to_value(s.importance).unwrap_or_default(),
                    })
                })
                .collect();
            jstring(
                &mut env,
                &json!({ "ok": true, "accounts": accounts }).to_string(),
            )
        }
        Err(e) => json_error(&mut env, &e),
    }
}

/// `create(input_json)` → `{"ok":true,"id":...}`；`input_json` 为 JSON 形式的 `AccountInput`。
#[no_mangle]
pub extern "system" fn Java_com_fuxipass_VaultBridge_create(
    mut env: JNIEnv,
    _: JClass,
    input_json: JString,
) -> jstring {
    let input: Result<vault_store::AccountInput, _> =
        serde_json::from_str(&jstr(&mut env, input_json));
    let input = match input {
        Ok(i) => i,
        Err(e) => return json_error(&mut env, &e.to_string()),
    };
    match with_vault(|v| v.create_account(&input)) {
        Ok(id) => jstring(&mut env, &json!({ "ok": true, "id": id }).to_string()),
        Err(e) => json_error(&mut env, &e),
    }
}

/// `delete(id)` → 1 成功 / 0 失败（软删除，移入回收站）。
#[no_mangle]
pub extern "system" fn Java_com_fuxipass_VaultBridge_delete(
    mut env: JNIEnv,
    _: JClass,
    id: JString,
) -> jboolean {
    let id = jstr(&mut env, id);
    match with_vault(|v| v.delete_account(&id)) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

/// `reveal(id, field)` → `{"ok":true,"value":...}` 或 `{"ok":false,...}`。
#[no_mangle]
pub extern "system" fn Java_com_fuxipass_VaultBridge_reveal(
    mut env: JNIEnv,
    _: JClass,
    id: JString,
    field: JString,
) -> jstring {
    let id = jstr(&mut env, id);
    let ft = vault_store::FieldType::parse(&jstr(&mut env, field));
    match ft {
        Some(ft) => match with_vault(|v| v.reveal_secret(&id, ft)) {
            Ok(value) => jstring(&mut env, &json!({ "ok": true, "value": value }).to_string()),
            Err(e) => json_error(&mut env, &e),
        },
        None => json_error(&mut env, "未知字段类型"),
    }
}

#[cfg(test)]
mod tests {
    // 桥接本身高度依赖 JVM，无法在宿主单测；这里仅验证可脱离 JVM 的纯逻辑。
    // 桥接方法的正确性由集成测试（Android 真机/模拟器）覆盖。

    use super::*;

    #[test]
    fn with_vault_requires_unlock() {
        // 未解锁时调用应返回 "未解锁"
        *VAULT.lock().unwrap() = None;
        let err = with_vault(|v| v.list_accounts()).unwrap_err();
        assert_eq!(err, "未解锁");
    }
}
