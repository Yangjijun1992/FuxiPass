# FuxiPass 移动端（Flutter + Rust FFI）

> ⚠️ **本目录是工程骨架，尚未编译验证**（生成环境无 Flutter SDK）。
> 设计说明见 [`../docs/07-移动端集成设计.md`](../docs/07-移动端集成设计.md)。

## 当前状态

| 部分 | 状态 |
| :-- | :-- |
| `lib/`（Dart UI + FFI 绑定声明） | 🔶 骨架已生成 |
| `vault_ffi/`（Rust 原生库） | ⬜ **待实现**（受 UB 门禁阻塞，见下） |
| Flutter 依赖安装 | ⬜ 未执行 |

## 前置条件

### 1. Rust 原生库（`vault_ffi`）—— 尚未实现

实现它需要先满足项目的 **UB 门禁**（编程规范要求：未经 Miri 验证不得发布 `unsafe`）：

```bash
rustup toolchain install nightly
rustup +nightly component add miri
```

> 本机只有发行版 `rustc 1.75`、无 rustup → 因此 FFI 代码**刻意未编写**，以免混入未验证的 `unsafe`。

### 2. Flutter SDK

```bash
# 参见 https://docs.flutter.dev/get-started/install
flutter --version
```

### 3. Android（可选）

- Android SDK + NDK
- Rust 交叉编译目标：`rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android`

## 构建步骤（工具链就绪后）

```bash
# 1) 编译 Rust 原生库（示例：Android arm64）
cd ../vault_ffi
cargo build --release --target aarch64-linux-android

# 2) 拷贝到 Flutter 工程的 jniLibs
mkdir -p ../mobile/android/app/src/main/jniLibs/arm64-v8a
cp target/aarch64-linux-android/release/libvault_ffi.so \
   ../mobile/android/app/src/main/jniLibs/arm64-v8a/

# 3) 运行 Flutter
cd ../mobile
flutter pub get
flutter run          # 或在 Linux 桌面端先验证 FFI 链路：flutter run -d linux
```

## 已验证路径（无需移动端）

移动端的核心逻辑（加密、存储、二次验证、备份）已在 PC 端完整验证：

```bash
cd .. && cargo test                    # 93 项测试
cargo run -p vault_web -- --db ~/FuxiPassVault/fuxipass.vault.db
```

因此移动端剩下的是**「搬运 + 平台能力」**，而非重新实现业务逻辑。

## 组件对应关系

| Flutter (Dart) | Rust |
| :-- | :-- |
| `lib/vault_backend.dart` | 抽象接口（与传输方式无关） |
| `lib/ffi/vault_ffi.dart` | 声明 `vault_ffi` 的 C ABI（见设计文档 §3） |
| `lib/main.dart` | 解锁 / 列表 / 详情（含二次验证对话框） |
| — | `vault_store` + `security_core`（已完成） |

## 已知平台差异（务必遵守）

| 能力 | Android | iOS |
| :-- | :-- | :-- |
| 防截图/录屏 | `FLAG_SECURE` ✅ | **无对等能力**，须如实告知用户（ADR-009） |
| 生物识别 | `BiometricPrompt` | `LocalAuthentication` |
| 硬件密钥库 | `AndroidKeyStore`（优先 StrongBox） | `Keychain`（`ThisDeviceOnly`） |
| 登录页抓取 | **不使用无障碍**（合规风险，ADR-007） | 不支持 |

## 下一步

1. **你确认**是否安装 `rustup` + `nightly` + `miri`（约 300MB）→ 我实现并验证 `vault_ffi`
2. 提供 Flutter SDK 环境后，先在 **Linux 桌面端**跑通 FFI 链路，再上 Android/iOS
