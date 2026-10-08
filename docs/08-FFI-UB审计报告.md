# `vault_ffi` UB 审计报告

> 依据编程规范的「unsafe 必须经 Miri 验证」要求出具。格式参照 `rust-ub` 参考的审计报告规范。

- **审计范围**：`vault_ffi`（移动端 FFI 层，C ABI）
- **Miri 版本**：`miri 0.1.0 (1d81eb4ad9 2026-10-07)`，`rustc 1.101.0-nightly`
- **日期**：2026-10-08
- **结论**：**Miri Level 1–4 全部通过 — 无未定义行为**

---

## 1. unsafe 资产清单（Phase 1 侦察）

| # | 位置 | 类别 | 风险 | 说明 |
| :-- | :-- | :-- | :-- | :-- |
| 1 | `convert.rs::cstr_to_string` | 8 — FFI 边界 | 中 | `CStr::from_ptr` 解引用 |
| 2 | `convert.rs::handle_ref` | 3/5 — 悬垂/非法值 | 高 | 句柄解引用为 `&mut` |
| 3 | `convert.rs::free_c_string` | 12 — 重复释放 | 高 | `CString::from_raw` |
| 4 | `lib.rs::fuxipass_unlock` | 8 | 中 | 入参转换 + `Box::into_raw` |
| 5 | `lib.rs::fuxipass_lock` | 3/12 | 高 | `Box::from_raw` |
| 6 | 各业务入口（list/get/create/update/delete/reveal/status） | 3/8 | 中 | 句柄 + 字符串转换 |
| 7 | `fuxipass_string_free` | 12 | 高 | 对外释放入口 |
| 8 | `error.rs::guard`（`catch_unwind` + `AssertUnwindSafe`） | 14 — 跨 FFI 展开 | 高 | panic 拦截 |

**总计**：`unsafe` 块 **11 处**、`unsafe fn` **4 个**、`unsafe impl` **0 个**。
全部集中在 `convert.rs`（转换）与对外入口的一行调用处；**无 `transmute`、无指针算术、无 `MaybeUninit`、无 `unsafe impl Send/Sync`**。

---

## 2. 设计上消除的 UB 类别

| 类别 | 消除方式 |
| :-- | :-- |
| 14 — unwinding across FFI | 所有 `extern "C"` 入口统一经 `guard()`；panic 被 `catch_unwind` 拦截并转为错误 JSON |
| 11 — provenance | 全程不把指针转成整数，无 provenance 丢失点 |
| 6 — 对齐 | 不跨边界传递结构体，**数据一律 JSON 字符串**，无对齐假设 |
| 10 — 越界 | 不使用指针算术；`CStr::from_ptr` 只读到首个 NUL |
| 9 — Send/Sync | 不使用 `unsafe impl`；句柄按「单线程持有」契约使用，错误槽为 `thread_local` |

---

## 3. Miri 验证（Phase 2）

测试集：`vault_ffi/tests/ffi_safety.rs`（8 项，**不触碰数据库**，故可在 Miri 下解释执行）。

| 级别 | 标志 | 结果 |
| :-- | :-- | :-- |
| **Level 1** | 默认（Stacked Borrows） | ✅ 8 passed |
| **Level 2** | `-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check` | ✅ 8 passed |
| **Level 3** | + `-Zmiri-preemption-rate=0.1 -Zmiri-backtrace=full -Zmiri-disable-isolation` | ✅ 8 passed |
| **Level 4** | + `-Zmiri-tree-borrows`（第二模型） | ✅ 8 passed |

执行命令（可复现）：

```bash
rustup toolchain install nightly --profile minimal --component miri,rust-src

# Level 3（审计标准）
MIRIFLAGS="-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check \
  -Zmiri-preemption-rate=0.1 -Zmiri-backtrace=full -Zmiri-disable-isolation" \
  cargo +nightly miri test -p vault_ffi --test ffi_safety

# Level 4（Tree Borrows）
MIRIFLAGS="-Zmiri-tree-borrows -Zmiri-strict-provenance \
  -Zmiri-symbolic-alignment-check -Zmiri-preemption-rate=0.1 \
  -Zmiri-backtrace=full -Zmiri-disable-isolation" \
  cargo +nightly miri test -p vault_ffi --test ffi_safety
```

被 Miri 覆盖的行为：
- 空指针 / 非法 UTF-8 入参 → 返回错误且不 panic
- `CString::into_raw` → `from_raw` 的一对一释放（无泄漏、无双释放）
- 错误槽的克隆与释放
- 全部 `extern "C"` 入口在错误路径上的内存行为

---

## 4. Miri 无法覆盖的部分（Phase 3 说明）

| 部分 | 原因 | 替代验证 |
| :-- | :-- | :-- |
| 触碰 SQLite 的流程 | SQLite 为 C 实现，Miri 无法解释 | `tests/ffi_flow.rs`（5 项原生测试，含完整 CRUD 与二次验证） |
| 跨语言调用（Dart/Kotlin/Swift） | 需移动端工具链 | 待 M2/M3 阶段在真机验证 |
| 线程并发持有句柄 | 当前契约为单线程持有 | 设计约束（见 `docs/07` §2）；未提供 `unsafe impl`，编译器强制 |

---

## 5. 审计中发现并修复的缺陷（非 UB，但影响安全）

| 缺陷 | 发现方式 | 修复 |
| :-- | :-- | :-- |
| **`fuxipass_reveal_secret` 未执行二次验证** —— 解析了主密码却没有校验，等于任何持有句柄者都能读取高敏感字段 | 编译器 `unused variable` 警告 | 句柄增加 `db_path`；揭示前调用 `verify_master_password`，失败返回 `UNAUTHORIZED`；新增测试断言「错误主密码不得揭示明文」 |

> 该缺陷若上线，会绕过 PRD §3.4.2 的二次验证要求。已由 `ffi_flow.rs::unlock_list_create_reveal_update_delete_flow` 锁定。

---

## 6. SAFETY 注释审查

所有 `unsafe` 块均带 SAFETY 注释，且满足规范要求的三要素：**类别 + 不变量 + 保证者**。

示例（`convert.rs::handle_ref`）：

```rust
/// # Safety
///
/// [分类 3/5 — 悬垂指针/非法值] `handle` 必须是 `fuxipass_unlock` 返回、
/// 且**尚未**经 `fuxipass_lock` 释放的非空指针；并且在本调用期间，
/// 调用方不得并发释放该句柄……（略）
pub unsafe fn handle_ref<'a>(handle: *mut FuxiHandle) -> Result<&'a mut FuxiHandle, FfiError> {
```

- [x] 每处 `unsafe` 均有 SAFETY 注释
- [x] 注释标注 UB 分类编号
- [x] 注释说明不变量与保证者（调用方契约 / 类型系统 / 运行时检查）
- [x] 无「we know this is safe」类空泛注释

---

## 7. 结论与后续

| 项 | 状态 |
| :-- | :-- |
| Miri Level 1–4 | ✅ 全部通过 |
| SAFETY 注释审查 | ✅ 完成 |
| 回归测试 | ✅ `ffi_safety.rs`（8 项）锁定边界行为 |
| CI 接入 Miri | ⬜ 待项目启用 CI 时加入（Level 2 起） |

**遗留事项**：
1. 本项目尚未有 CI；建议后续加入 `cargo +nightly miri test -p vault_ffi --test ffi_safety`（Level 2 起）。
2. 移动端真机联调（M2/M3）后，建议补充跨语言边界的行为测试。
