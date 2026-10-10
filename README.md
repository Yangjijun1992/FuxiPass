# FuxiPass · 安全密码管家

[![ci](https://github.com/Yangjijun1992/FuxiPass/actions/workflows/ci.yml/badge.svg)](https://github.com/Yangjijun1992/FuxiPass/actions/workflows/ci.yml)

> **零知识、本地强加密、灾难可恢复**的个人账户与密码管理项目。

一个面向 Android / iOS 的密码管理器项目：主密码永不上云、数据全程本地加密，并提供
**密码提示词 / 本地恢复码 / 邮箱短信验证** 三条恢复通道，确保「主密码遗忘 ≠ 数据丢失」。

配套一个 **PC 端本地 Web 验证界面**，可在没有移动工具链时直接体验解锁、检索、查看、增删与二次验证。

---

## 项目状态

| 模块 | 状态 | 说明 |
| :-- | :-- | :-- |
| 需求与设计文档 | ✅ 完成 | PRD V2.0 + 架构规格 + 任务清单 + 验收用例 + 接口定义 + ADR |
| `security_core`（加密核心） | ✅ 完成 | Argon2id / AES-256-GCM / 分层密钥 / 包裹 / 恢复 |
| `vault_store`（数据层） | ✅ 完成 | SQLite + 字段级加密 + 卡片 CRUD/检索/审计 + 智能导入 + **防爆破锁定 + 加密备份** |
| `vault_web`（PC 验证界面） | ✅ 完成 | 解锁/检索/增删/二次验证/审计 + 提示词 + 恢复码轮换 + 智能导入 + 剪贴板策略 + **备份/迁移** |
| `vault_cli`（离线运维） | ✅ 完成 | 批量导入 / 列表 / 导出与恢复备份 / 改密 / 删除 / **恢复密钥重置** |
| `vault_ffi`（移动端桥接） | ✅ 完成 | 11 个 C ABI 符号；**Miri Level 1–4 验证无 UB** |
| `recovery_service`（找回服务） | ✅ 完成 | 零知识：仅存不可逆哈希 + 加密包裹；**SQLite 持久化（重启不丢绑定）**；一次性验证码/令牌 + 限流；事件日志与健康检查；已接入网页端：邮箱绑定 + 验证码找回闭环 + **真实 SMTP 投递**（经 curl，兼容 QQ/163/Gmail 授权码；授权码仅从文件读取、不进 argv、发完即删） |
| 移动端 App（Flutter + 原生） | ⬜ 未开始 | 需 Flutter / Android SDK / Xcode 工具链 |
| 服务端（可选找回通道） | ⬜ 未开始 | 零知识设计已就绪（docs/04） |

**测试**：**150+ 项全绿**（含「凭证字段无明文」「备份无明文」「20 次输错后数据完好」等红线断言）。
**CI**：GitHub Actions 四项检查（fmt / clippy `-D warnings` / test / **Miri**）。
**任务进度**：Phase 1 基本完成；Phase 2 全部完成（含找回服务）；Phase 3 之 T3.6（加密备份）完成；Phase 4 之审计与 PIPL 完成。

---

## 目录结构

```
FuxiPass/
├── Cargo.toml                    # workspace
├── reference.md                  # PRD V2.0（安全加固版）
├── reference.orig.md             # PRD V1.0 原稿（存档）
├── docs/                         # 需求 / 架构 / 任务 / 用例 / 接口 / ADR
├── security_core/                # 加密核心库
│   ├── src/  cipher · kdf · keys · wrap · seal · vault · bytes · error
│   ├── tests/                    # 端到端验收测试
│   └── examples/vault_demo.rs
├── vault_store/                  # 数据层（SQLite + 字段级加密 + Repository）
│   ├── src/  schema · models · vault · accounts · audit
│   └── tests/integration.rs
└── vault_web/                    # PC 端本地 Web 验证界面
    ├── src/  main · api · state · middleware · index.html
    └── (仅监听 127.0.0.1)
```

---

## 快速开始

### 环境要求

- Rust **1.75+**
  （依赖已钉版兼容较旧工具链：`base64ct =1.6.0`、`zeroize ~1.4`、`thiserror =2.0.20`）

### 一、运行测试

```bash
cargo test          # 114 项
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

### 二、加密核心演示（无界面）

```bash
cd security_core
cargo run --example vault_demo
```

输出密钥包裹 JSON、恢复密钥显示串，并验证「解锁 / 恢复 / 改密」三种流程。

### 三、离线运维 CLI

```bash
# 批量导入文本
cargo run -p vault_cli -- import --db ./fuxipass.vault.db --text private/account_list.normalized.txt

# 导出 / 恢复加密备份（换机迁移）
cargo run -p vault_cli -- export        --db ./fuxipass.vault.db --out backup.json
cargo run -p vault_cli -- import-backup --db ./new-vault.db     --in  backup.json

# 修改主密码（仅重包 DEK，不重加密数据）
cargo run -p vault_cli -- change-password --db ./fuxipass.vault.db
```
所有口令建议通过 `--password-file` 传入，避免终端回显与 shell 历史留痕。

### 四、PC 端 Web 验证界面（推荐）

```bash
# 首次运行：创建演示库并写入示例账号（会打印恢复密钥，请保存）
cargo run -p vault_web -- --db ./fuxipass.vault.db --port 8787 --seed-demo "demo-master-123"

# 或使用已有库启动
cargo run -p vault_web -- --db ./fuxipass.vault.db --port 8787
```

浏览器打开 **http://127.0.0.1:8787**，即可：

| 功能 | 说明 |
| :-- | :-- |
| 创建保险库 | 设主密码 → 得到恢复密钥（仅显示一次，可复制/打印） |
| 解锁 / 锁定 | 主密码解锁；支持密码提示词 |
| 忘记密码恢复 | 用恢复密钥 + 新主密码重置（数据不丢） |
| **恢复密钥轮换** | 二次验证后可重新生成；旧密钥立即失效，支持复制/打印 |
| **密码提示词** | 解锁失败时显示（明文保存，UI 强警示勿写密码，见 ADR-012） |
| 检索 | 平台名 / 网址 / 账号模糊匹配（如 `建设`、`ccb`、`zhangsan`） |
| 查看详情 | 密码以 `88****` 脱敏展示 |
| 解锁查看 | 高敏感字段需**再次输入主密码**（二次验证），并写入审计 |
| **剪贴板策略** | 复制后 30 秒自动清空；高敏感字段复制前强警示 |
| **智能导入** | 粘贴 QQ 记事本/备忘录文本 → 自动解析 → 可编辑预览 → 二次验证后批量入库 |
| 新增 / 编辑 / 删除 | 完整卡片 CRUD |
| 审计日志 | 记录操作与字段类别，**不含任何明文** |
| **防爆破锁定** | 连续输错 5 次锁 5 分钟并指数退避至 30 分钟上限；界面显示倒计时；**绝不删除数据** |
| **备份 / 迁移** | 导出为口令加密文件（无明文）；新机器一键导入恢复 |

> ⚠️ 仅供本地验证：服务仅绑定 `127.0.0.1`。生产形态为移动端 App（见 docs/01）。

---

## 核心安全设计

| 机制 | 实现 |
| :-- | :-- |
| **分层密钥体系** | 主密码 → Argon2id → KEK → 包裹 DEK；DEK 实际加密数据 |
| **字段级加密** | 每个敏感列（平台名/账号/备注/各类密码）独立 AES-256-GCM 加密后落库 |
| **改密不重加密全量** | 仅用新 KEK 重新包裹 DEK，DEK 保持不变 |
| **灾难可恢复** | RecoveryKey（256-bit）独立包裹 DEK；忘记主密码可解包重设 |
| **零知识边界** | 服务端只存不可逆哈希 + 包裹密文，永不可解密 |
| **二次验证** | 极高敏感字段揭示需再次校验主密码（重派生 KEK 试解 DEK） |
| **防篡改** | AES-256-GCM 认证加密，任何密文改动都会被拒绝 |
| **密钥内存安全** | `zeroize` 擦除 + 密钥类型不实现 `Debug`，防止日志泄露 |
| **防爆破不毁数据** | 仅指数退避锁定，**绝不自动删除/清空用户数据**（硬红线） |
| **审计不留明文** | 只记录操作类型与字段类别 |

### 已验证的安全性质

- 数据库文件扫描：`888444`、`Ccb@2024Login`、`中国建设银行`、`zhangsan_123` 等**凭证字段均无明文**。
- 未授权访问 → 401；锁定后访问 → 423；鉴权先于请求体解析。
- 错误主密码 / 错误恢复密钥 / 被篡改密文 → 一律拒绝。
- 改密与恢复后，原数据完整可读且 DEK 不变。
- 恢复码轮换后旧码立即失效、新码可用；导入的账号同样密文落库。

> ⚠️ **例外说明**：密码提示词（Hint）按设计为**明文存储**——它必须在解锁前可见，无法用 DEK 加密（见 ADR-012）。
> UI 在保存时会强警示「勿写入密码本身」。

---

## 文档索引

| 想了解 | 看这里 |
| :-- | :-- |
| 产品需求、安全原则、验收标准 | [`reference.md`](reference.md) |
| 系统架构、模块划分、威胁模型 | [`docs/01-架构规格书.md`](docs/01-架构规格书.md) |
| 开发任务、依赖、工作量 | [`docs/02-开发任务清单.md`](docs/02-开发任务清单.md) |
| 测试用例、必过红线 | [`docs/03-验收测试用例清单.md`](docs/03-验收测试用例清单.md) |
| 数据库表结构、找回接口 | [`docs/04-数据库与远程接口.md`](docs/04-数据库与远程接口.md) |
| 关键决策与权衡记录 | [`docs/06-架构决策记录ADR.md`](docs/06-架构决策记录ADR.md) |

---

## 路线图

| Phase | 内容 | 状态 |
| :-- | :-- | :-- |
| **P1** 安全底座 | 密钥体系、加密核心、存储与 CRUD、提示词/恢复码、剪贴板 | ✅ PC 端完成 |
| **P2** 分级鉴权 / 找回 / 导入 | 二次验证、防爆破、邮箱短信找回、文本解析 | ✅ 全部完成（找回服务已实现并通过端到端验证） |
| **P3** 抓取与系统集成 | 登录页抓取、AutoFill、加密备份导出恢复 | 🔶 **加密备份已完成**；抓取/AutoFill 需移动端 |
| **P4** 加固与审计 | 防截图、剪贴板强化、审计日志、PIPL 合规 | 🔶 审计查询/导出 + PIPL 数据权利已完成；防截图需移动端 |

---

## 已知约束

1. 移动端需 Flutter + Android SDK / Xcode 工具链；本仓库当前提供可独立验证的 Rust 核心、数据层与 PC Web 界面。
2. 上游加密依赖的最新版要求 Rust 1.85+/edition2024，本项目已钉版兼容 1.75；升级工具链后可解除钉版。
3. **PC 原型的静态加密由应用层字段级加密承担**（DEK 不入库）；SQLCipher 数据库级加密列为移动端生产加固项（见 ADR-011）。
4. `vault_web` 为本地验证原型，非生产形态，仅监听 127.0.0.1。

---

## 许可

Apache-2.0 OR MIT
