# 11 · HarmonyOS 交叉编译 PoC

> 目的：在**不购买鸿蒙真机**的情况下，验证 FuxiPass 的 Rust 核心能否交叉编译到
> 鸿蒙（HarmonyOS NEXT，`aarch64-unknown-linux-ohos`），以消除「理论可行还是
> 实际可行」的残余不确定性。
>
> 结论：**代码层面完全可行，仅剩工具链链接一步**。详见下文。

---

## 0. 结论速览

| 项 | 结果 |
| :-- | :-- |
| Rust 官方 target `aarch64-unknown-linux-ohos` | ✅ Tier 2，本机已验证可安装 |
| `security_core`（纯 Rust 加密核心） | ✅ **交叉编译成功**（产出 ohos 的 `.rlib`，零 C 依赖、零 SDK） |
| `rusqlite[bundled]`（SQLite C 代码） | ✅ **交叉编译成功**（`libsqlite3-sys` 为 ohos 构建通过） |
| 全部依赖 crate（argon2/aes-gcm/serde…） | ✅ 为 ohos 交叉编译成功 |
| **最终链接 `libvault_ffi.so`** | ⚠️ **需要 OHOS 工具链**（链接器 + libc sysroot） |

**含义**：FuxiPass 的整条技术栈（纯 Rust + 无 OpenSSL + bundled SQLite）对鸿蒙
**无需任何代码改动**；跨到 `.so` 只差「链接器 + libc」，这两个由 **OpenHarmony SDK /
DevEco Studio** 提供。

---

## 1. 已验证（本仓库实际操作）

### 1.1 官方 target 可用

```bash
rustup target add aarch64-unknown-linux-ohos
# => ok（nightly 1.101 内置该 target，Tier 2）

rustc --print target-list | grep ohos
# aarch64-unknown-linux-ohos
# armv7-unknown-linux-ohos
# x86_64-unknown-linux-ohos
# loongarch64-unknown-linux-ohos
```

### 1.2 纯 Rust 加密核心交叉编译成功

```bash
cargo build -p security_core --target aarch64-unknown-linux-ohos
# => Finished, 产出 target/aarch64-unknown-linux-ohos/debug/libsecurity_core.rlib (2.2 MB)
```

证明 `security_core`（Argon2id / AES-256-GCM / 密钥包裹）可在鸿蒙工具链上编译、
不依赖 OpenSSL / 不依赖系统 C 库头文件。

### 1.3 含 SQLite 的完整依赖树交叉编译成功

```bash
cargo build -p vault_ffi --target aarch64-unknown-linux-ohos
```

- 所有依赖 crate 均产出 ohos 的 `.rlib` ✅
- **`libsqlite3-sys`（SQLite C 代码，经 `cc` 编译）成功** ✅ —— 证实
  `rusqlite[bundled]` 在鸿蒙目标上可编译，是本方案最不确定的一环，已被验证。

### 1.4 唯一失败点：最终链接

```
error: linking with `clang` failed
  /usr/bin/ld: ... Relocations in generic ELF (EM: 183)
```

- `EM: 183` = `EM_AARCH64` —— **宿主 `ld`（x86_64）不是 aarch64 链接器**，无法链接
  已编译好的 aarch64 目标文件。
- 且本机 clang 为 **10.0**：不支持 `lld`，系统也未装 `aarch64-linux-gnu-gcc`。

---

## 2. 剩余工作：拿到 OHOS 工具链即可完成链接

链接一个鸿蒙 `.so` 需要两样东西，均来自 **OpenHarmony SDK**（装 DevEco Studio 即得）：

| 需要 | 来源 | 说明 |
| :-- | :-- | :-- |
| **aarch64 链接器** | SDK `native/llvm/bin/ld.lld` | 用 `lld` 链接 aarch64 对象 |
| **OHOS libc sysroot** | SDK `native/sysroot` | 提供 `-lc`、`-lunwind` 及 `<stdio.h>` 等 |

### 完整配方（在装有 OHOS SDK 的机器上，如 Mac + DevEco）

```bash
export OHOS_SDK=/path/to/ohos-sdk   # e.g. ~/Library/Huawei/Sdk
export CC_aarch64_unknown_linux_ohos="$OHOS_SDK/native/llvm/bin/clang"

# .cargo/config.toml
# [target.aarch64-unknown-linux-ohos]
# linker = "$OHOS_SDK/native/llvm/bin/clang"
# rustflags = [
#   "-C", "link-arg=--target=aarch64-linux-ohos",
#   "-C", "link-arg=-fuse-ld=lld",
#   "-C", "link-arg=--sysroot=$OHOS_SDK/native/sysroot",
# ]

cargo build -p vault_ffi --release --target aarch64-unknown-linux-ohos
# 产出 libvault_ffi.so —— 直接交给 ArkTS/NAPI 壳层
```

> 提示：`ohos-rs`（napi-rs 的鸿蒙 fork）会在 `cargo build` 时**自动**从
> `$OHOS_SDK_PATH/native` 读取工具链，通常无需手写上述 rustflags：
> `cargo add napi-ohos napi-derive-ohos && ohrs build -a aarch`。

---

## 3. 为什么不在这台服务器完成链接

| 阻碍 | 说明 |
| :-- | :-- |
| `lld` 不可用 | 本机 clang 10.0 不支持 `-fuse-ld=lld`，未装 ld.lld |
| 无 aarch64 交叉 GNU 工具链 | 未装 `aarch64-linux-gnu-gcc` |
| 无 OHOS sysroot | OpenHarmony SDK 未安装（体积大、需网络下载与授权） |
| 无 sudo | 无法系统级安装缺失工具 |

此三步均非代码问题；在没有 SDK 的情况下，我们已经把**所有可证实的部分证完**。

---

## 4. 建议的下一步（可选）

在装有 DevEco Studio 的 Mac 上复跑一次完整链接：

```bash
cd ~/Developer/FuxiPass
git pull
cargo build -p vault_ffi --release --target aarch64-unknown-linux-ohos
```

- 成功 → 得到 `libvault_ffi.so`，即可开始 ArkTS/NAPI 壳层与 UI 开发。
- 失败 → 报错会指向具体缺失项，对照 §2 配方补齐即可。

> 若想更早验证链接，可临时装一个 AMD64 的 aarch64-linux GNU 工具链配合 Clang 的
> `--sysroot` 做**近似链接**（非 OHOS libc），但这只能开发期用，不建议作为验收。

---

## 5. 相关文档

| 想了解 | 看这里 |
| :-- | :-- |
| 鸿蒙部署可行性完整调研 | 对话内调研报告（ArkTS + ohos-rs 路线） |
| FFI 桥接（11 个 C ABI 符号） | [`07-移动端集成设计.md`](07-移动端集成设计.md) |
| 在 Mac 上开发维护 | [`10-macOS-开发与维护.md`](10-macOS-开发与维护.md) |
| 系统架构 | [`01-架构规格书.md`](01-架构规格书.md) |
