# 10 · macOS 开发与维护指南

> 目标：把 macOS 作为**主开发机**，同时保证正式数据不受开发操作影响。
> 适用对象：需要长期维护本项目的开发者（含未来的你自己）。

---

## 0. 核心理念：开发与运行分离

```
~/Developer/FuxiPass/      ← 源码目录（git 仓库；只管代码，可随时删除重建）
~/fuxipass/                ← 运行目录（二进制 + data/ 正式库；不放源码）
```

> ⚠️ **第一红线**：开发调试时**永远不要**把服务指向正式库 `~/fuxipass/data/`。
> 调试请使用 `/tmp` 下的一次性测试库（见 §5）。

两条独立路径，互不干扰：

| 路径 | 用途 | 数据风险 |
| :-- | :-- | :-- |
| **开发** `~/Developer/FuxiPass` | 写代码、跑测试、提交 | 无（用临时库） |
| **运行** `~/fuxipass` | 日常使用、存正式数据 | 高（务必远离开发操作） |

---

## 1. 工具链准备

```bash
# ① Xcode 命令行工具（git / cc / make 均来自它）
xcode-select --install
git --version                     # 应输出版本号

# ② Rust 工具链（本项目要求 1.75+，建议 stable）
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version && cargo --version

# ③ 格式化与静态检查组件
rustup component add rustfmt clippy
```

> 服务端为 macOS：无额外系统依赖（不依赖 OpenSSL、不依赖 SQLCipher —— 加密与存储全部由 Rust 实现）。

---

## 2. GitHub 访问配置

推送需要凭据。选一种：

| 方式 | 有效期 | 推荐度 |
| :-- | :-- | :-- |
| **SSH 密钥** | 长期 | ⭐⭐⭐ 推荐 |
| PAT（个人访问令牌） | 可设过期 | ⭐⭐ |
| 仅克隆（只读） | — | ⭐ 仅用于编译 |

### 2.1 SSH 密钥（推荐）

```bash
ssh-keygen -t ed25519 -C "你的邮箱"          # 一路回车（可留空口令）
pbcopy < ~/.ssh/id_ed25519.pub               # macOS：复制公钥到剪贴板

# GitHub → 右上头像 → Settings → SSH and GPG keys → New SSH key → 粘贴 → 保存
ssh -T git@github.com                        # 看到 "Hi <用户名>!" 即成功
```

### 2.2 PAT（备选）

GitHub → Settings → Developer settings → Personal access tokens → 生成（勾选 `repo` 权限）。
推送时用户名填 GitHub 用户名，密码填令牌。建议存入 macOS 钥匙串（首次推送时会询问）。

---

## 3. 克隆与身份配置

```bash
mkdir -p ~/Developer && cd ~/Developer
git clone git@github.com:Yangjijun1992/FuxiPass.git
cd FuxiPass

git config user.name  "你的名字"
git config user.email "你的邮箱"
```

> 仓库若为**公开**，克隆无需凭据；若为**私有**，需先完成 §2 的凭据配置。

---

## 4. 环境自检

### 4.1 一键就绪体检（推荐）

```bash
bash scripts/check-dev-ready.sh
```

脚本逐项检查工具链、编译、测试、质量门禁与运行冒烟，并给出结论：

```
[6/6] 总结
  通过：17 项   未通过：0 项

  ✅ 这台机器已具备完整的开发与维护能力。
```

- 全程使用**临时目录**，**不触碰正式数据库**，不需要 sudo，不需要 git 仓库
- 未通过项会直接给出修复命令（如 `rustup component add clippy`）
- 换新机器、升级系统后，建议先跑一遍确认环境完好

### 4.2 手动三条命令

```bash
cargo test --workspace                                   # 全部测试
cargo clippy --all-targets -- -D warnings                # 静态检查（零警告要求）
cargo fmt --all -- --check                               # 格式检查
```

三项全过 = 开发环境就绪。

> 提示：`cargo test --workspace` 输出较长，判断是否全绿请检查**退出码**与 `test result: FAILED` 字样，
> 不要只看末尾几行（失败目标可能出现在中间）。

---

## 5. 本地调试（务必用临时库）

```bash
# 网页端：用 /tmp 下的一次性库 + 演示数据
cargo run -p vault_web -- --db /tmp/dev.vault.db --port 8788 --seed-demo "dev-master-123"

# 找回服务（另开终端）
cargo run -p recovery_service -- --port 8798 --db /tmp/dev-recovery.db --dev-echo-code
```

- `--seed-demo` 会创建演示库并**打印恢复密钥**（仅测试用）
- `--dev-echo-code` 让验证码直接回显到页面，**无需真实邮箱**
- 端口用 **8788/8798**，与正式环境的 **8787/8799** 错开，避免混淆

> ⚠️ `--dev-echo-code` 仅限本地调试，**绝不可用于正式环境**。

---

## 6. 日常开发闭环

```bash
git pull origin main                        # ① 同步最新

git checkout -b feat/功能名                  # ② 建分支（不要直接改 main）

# … 修改代码 …

cargo fmt --all                             # ③ 格式化
cargo test --workspace                      #    测试
cargo clippy --all-targets -- -D warnings   #    静态检查

git add -A                                  # ④ 提交
git commit -m "feat: 说明本次改动"

git push origin feat/功能名                  # ⑤ 推送 → CI 自动运行
# ⑥ 在 GitHub 开 Pull Request，CI 全绿后合并到 main
```

### 提交信息约定

| 前缀 | 用途 |
| :-- | :-- |
| `feat:` | 新功能 |
| `fix:` | 修复缺陷 |
| `docs:` | 仅文档变更 |
| `refactor:` | 重构（不改变行为） |
| `test:` | 仅测试变更 |
| `chore:` | 构建/配置等杂项 |

---

## 7. 出正式版本（替换运行目录）

```bash
cd ~/Developer/FuxiPass
git pull origin main
cargo build --release --bin vault_web --bin vault_cli --bin recovery_service

# 备份旧二进制后替换（data/ 目录保持不动）
cp target/release/vault_web         ~/fuxipass/
cp target/release/vault_cli         ~/fuxipass/
cp target/release/recovery_service  ~/fuxipass/
```

首次运行若提示"来自身份不明的开发者"：

```bash
xattr -d com.apple.quarantine ~/fuxipass/vault_web
xattr -d com.apple.quarantine ~/fuxipass/vault_cli
xattr -d com.apple.quarantine ~/fuxipass/recovery_service
```

### 版本确认

网页端页脚会显示 `界面版本 <git短SHA>`。与源码目录 `git rev-parse --short HEAD` 一致，即表示运行的是最新构建。

---

## 8. 双机协作规范（Linux ↔ macOS）

| 对象 | 同步方式 | 说明 |
| :-- | :-- | :-- |
| **代码** | ✅ 仅通过 GitHub | 唯一真相来源；两边都 `git pull` |
| **正式数据库** | ❌ **不用 git** | `.gitignore` 已排除；绝不入库 |
| 数据迁移 | ✅ 加密备份（导出/恢复） | 可经云盘、U 盘等任何通道 |
| 二进制 | ❌ 不互传 | x86_64 与 ARM64 不通用，各自编译 |

> ⚠️ **避免数据分叉**：请**只选定一台机器作为"正式机"**承载正式库。
> 另一台仅用于开发（或仅持有加密备份）。两台同时维护各自一份库会导致数据不一致。

### 数据迁移（换机 / 备份）

```bash
# 源机器：导出口令加密的备份文件（内容全为密文）
cargo run -p vault_cli -- export --db ~/fuxipass/data/fuxipass.vault.db --out backup.json

# 目标机器：导入
cargo run -p vault_cli -- import-backup --db ~/fuxipass/data/fuxipass.vault.db --in backup.json
```

口令请通过文件传入，避免终端回显与 shell 历史留痕：

```bash
printf '你的备份口令' > /tmp/backup.pass && chmod 600 /tmp/backup.pass
cargo run -p vault_cli -- export --db ~/fuxipass/data/fuxipass.vault.db --out backup.json --password-file /tmp/backup.pass
rm -f /tmp/backup.pass
```

---

## 9. 私有仓库的注意事项

仓库设为 **Private** 后有两处变化：

### 9.1 克隆/推送需凭据

按 §2 配置 SSH 或 PAT 后方可操作（公开仓库时克隆无需凭据）。

### 9.2 GitHub Actions 分钟数会计费

| 仓库类型 | Actions 额度 |
| :-- | :-- |
| 公开 | 标准 runner **免费不限量** |
| **私有** | 免费额度 2000 分钟/月；**macOS runner 按 10× 计费** |

> 即：私有仓库下，一次 macOS 构建（约 5 分钟）≈ 消耗 50 分钟额度。
> 免费额度约可支撑 **30–40 次** macOS 构建/月。

**应对**：macOS 二进制**优先本地编译**（§7 三条命令即可），CI 仅作备份手段。
本地编译不消耗任何额度。

### 9.3 私密信息检查

设为私有**不等于**可以提交敏感信息 —— 一旦将来转回公开或添加协作者，历史仍会暴露。提交前请确认：

```bash
git status --short                      # 查看将要提交的文件
git ls-files | grep -iE "\.db$|\.pass$|backup.*\.json|private/"   # 应为空
```

红线（**永不入库**）：

- 任何 `.db` / `.sqlite` 数据库文件
- 任何密码、授权码、令牌、私钥
- 恢复密钥、备份文件
- `private/` 目录下的个人资料

---

## 10. 常见问题

| 现象 | 原因与处理 |
| :-- | :-- |
| `xcode-select: error` | 未装命令行工具 → `xcode-select --install` |
| `git push` 报权限错误 | 未配 SSH 或 PAT → 见 §2 |
| 编译报 edition2024 相关错误 | Rust 版本过旧 → `rustup update stable`（需 1.75+） |
| 页面显示旧版本 | 浏览器缓存（强制刷新）或运行目录二进制未替换 |
| 端口被占用 | 正式 8787/8799 与调试 8788/8798 是否混用 |
| `cargo test` 失败但看不出 | 检查**退出码**与 `test result: FAILED`（可能在中段输出） |

---

## 11. 一页速查

```bash
# ── 首次准备 ──
xcode-select --install
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
ssh-keygen -t ed25519 -C "你的邮箱" && pbcopy < ~/.ssh/id_ed25519.pub   # 贴到 GitHub
mkdir -p ~/Developer && cd ~/Developer && git clone git@github.com:Yangjijun1992/FuxiPass.git

# ── 环境自检 ──
cd ~/Developer/FuxiPass
cargo test --workspace && cargo clippy --all-targets -- -D warnings && cargo fmt --all -- --check

# ── 本地调试（临时库，端口错开）──
cargo run -p vault_web -- --db /tmp/dev.vault.db --port 8788 --seed-demo "dev-master-123"

# ── 日常开发 ──
git pull origin main && git checkout -b feat/xxx
# … 改代码 …
cargo fmt --all && cargo test --workspace && cargo clippy --all-targets -- -D warnings
git add -A && git commit -m "feat: xxx" && git push origin feat/xxx

# ── 出正式版本 ──
cargo build --release --bin vault_web --bin vault_cli --bin recovery_service
cp target/release/{vault_web,vault_cli,recovery_service} ~/fuxipass/
```

---

## 12. 相关文档

| 想了解 | 看这里 |
| :-- | :-- |
| 日常使用（绑定/找回/备份） | [`09-使用指南.md`](09-使用指南.md) |
| 系统架构与威胁模型 | [`01-架构规格书.md`](01-架构规格书.md) |
| 数据库结构与接口 | [`04-数据库与远程接口.md`](04-数据库与远程接口.md) |
| 关键决策记录 | [`06-架构决策记录ADR.md`](06-架构决策记录ADR.md) |
