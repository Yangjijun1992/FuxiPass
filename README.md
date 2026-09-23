# FuxiPass · 安全密码管家

> **零知识、本地强加密、灾难可恢复**的个人账户与密码管理项目。

一个面向 Android / iOS 的密码管理器项目：主密码永不上云、数据全程本地加密，并提供
**密码提示词 / 本地恢复码 / 邮箱短信验证** 三条恢复通道，确保「主密码遗忘 ≠ 数据丢失」。

---

## 项目状态

| 维度 | 状态 |
| :-- | :-- |
| 需求与设计文档 | ✅ 完整（PRD V2.0 + 架构规格 + 任务清单 + 验收用例 + 接口定义 + ADR） |
| 加密核心库 `security_core` | ✅ 已实现并通过 35 项测试 |
| 移动端 App（Flutter + 原生） | ⬜ 未开始（本仓库环境无 Flutter/Android/iOS 工具链） |
| 服务端（可选找回通道） | ⬜ 未开始 |

当前编码进度：**2 / 33 任务**（Phase 1 加密地基完成）。

---

## 目录结构

```
FuxiPass/
├── reference.md                  # PRD V2.0（安全加固版，含验收标准 §8）
├── reference.orig.md             # PRD V1.0 原稿（存档）
├── docs/
│   ├── 01-架构规格书.md           # 分层架构、密钥体系、模块、威胁模型
│   ├── 02-开发任务清单.md         # 33 任务 / 172 人天 / 四个 Phase
│   ├── 03-验收测试用例清单.md     # 41 条可执行用例 + 必过红线
│   ├── 04-数据库与远程接口.md     # SQLCipher 表结构 + 零知识找回 API
│   ├── 05-任务Issue模板.md        # GitHub Issue / CSV 导入模板
│   └── 06-架构决策记录ADR.md      # 10 条关键决策与权衡
└── security_core/                # Rust 加密核心库（Foundation）
    ├── src/
    │   ├── cipher.rs             # AES-256-GCM 认证加密
    │   ├── kdf.rs                # Argon2id 密钥派生
    │   ├── keys.rs               # Kek / Dek / AccountKey / RecoveryKey
    │   ├── wrap.rs               # 密钥包裹结构与 JSON 序列化
    │   ├── vault.rs              # 顶层编排：初始化 / 改密 / 恢复
    │   ├── bytes.rs / error.rs / lib.rs
    ├── tests/integration.rs      # 端到端验收测试
    └── examples/vault_demo.rs    # 可运行示例
```

---

## 核心安全设计

| 机制 | 实现 |
| :-- | :-- |
| **分层密钥体系** | 主密码 → Argon2id → KEK → 包裹 DEK；DEK 实际加密数据 |
| **改密不重加密全量** | 仅用新 KEK 重新包裹 DEK，DEK 保持不变 |
| **灾难可恢复** | RecoveryKey（≥256-bit）独立包裹 DEK；忘记主密码可解包重设 |
| **零知识边界** | 服务端只存不可逆哈希 + 包裹密文，永不可解密 |
| **防篡改** | AES-256-GCM 认证加密，任何密文改动都会被拒绝 |
| **密钥内存安全** | `zeroize` 擦除 + 密钥类型不实现 `Debug`，防止日志泄露 |
| **语义隔离** | 不同用途密钥为独立 newtype，编译期禁止混用 |
| **防爆破不毁数据** | 仅指数退避锁定，**绝不自动删除/清空用户数据**（硬红线） |

---

## 快速开始

### 环境要求

- Rust **1.75+**（当前依赖已钉版以兼容较旧工具链：`base64ct =1.6.0`、`zeroize ~1.4`）

### 运行

```bash
cd security_core

# 运行全部测试（35 项）
cargo test

# 运行端到端示例：初始化 → 打印包裹 JSON → 解锁/恢复/改密验证
cargo run --example vault_demo
```

示例输出（节选）：

```json
{
  "version": 1,
  "kdf": { "algorithm": "argon2id", "salt": "…", "m_cost_kib": 19456, "t_cost": 2, "p_cost": 1 },
  "cipher": { "algorithm": "aes-256-gcm", "nonce": "…", "tag": "…" },
  "ciphertext": "…"
}
```

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
| **P1** 安全底座 | 密钥体系、加密库、本地存储、CRUD、提示词/恢复码 | 🔶 加密核心已完成 |
| **P2** 分级鉴权 / 找回 / 导入 | 二次验证、邮箱短信找回、QQ 记事本解析 | ⬜ |
| **P3** 抓取与系统集成 | 登录页抓取、AutoFill、加密备份导出恢复 | ⬜ |
| **P4** 加固与审计 | 防截图、剪贴板强化、审计日志、PIPL 合规 | ⬜ |

---

## 已知约束

1. 移动端需 Flutter + Android SDK / Xcode 工具链方可构建；本仓库当前仅含可独立验证的 Rust 加密核心。
2. 上游加密依赖的最新版要求 Rust 1.85+/edition2024，本项目已钉版兼容 1.75；升级工具链后可解除钉版。
3. `security_core` 为库，`Cargo.lock` 已入库以保证依赖版本可复现。

---

## 许可

Apache-2.0 OR MIT
