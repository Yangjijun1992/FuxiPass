#!/usr/bin/env bash
# 组装 FuxiPass 部署包（供拷贝到另一台 x86_64 Linux 电脑使用）。
#
# 用法：bash scripts/package-deploy.sh [输出目录]
# 产物：<输出目录>/fuxipass-deploy/ 与 fuxipass-deploy.tar.gz
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_BASE="${1:-$ROOT/deploy}"
PKG="$OUT_BASE/fuxipass-deploy"

echo "==> 1/4 构建 release 二进制"
(cd "$ROOT" && cargo build --release --quiet)

echo "==> 2/4 组装目录 $PKG"
rm -rf "$PKG"
mkdir -p "$PKG/bin" "$PKG/data"

for bin in vault_web vault_cli recovery_service; do
  cp "$ROOT/target/release/$bin" "$PKG/bin/$bin"
  chmod 755 "$PKG/bin/$bin"
done

echo "==> 3/4 写入部署说明"
cat > "$PKG/部署步骤.md" <<'GUIDE'
# FuxiPass 部署步骤（目标电脑执行）

> 适用：x86_64 Linux，glibc ≥ 2.35（Ubuntu 22.04+ / Debian 12+ / Rocky 9+）。
> 若目标机 glibc 更旧，请改为「从源码构建」（见文末）。

## 0. 前置检查

```bash
ldd --version | head -1        # 需 ≥ 2.35
uname -m                       # 需 x86_64
```

## 1. 放置文件

把本包解压到目标机器（例如 `~/fuxipass`）：

```bash
mkdir -p ~/fuxipass && tar -xzf fuxipass-deploy.tar.gz -C ~/fuxipass --strip-components=1
cd ~/fuxipass
chmod 700 data
```

## 2. 恢复你的保险库

需要两样东西：**从旧机器导出的加密备份** + **备份口令**。

```bash
./bin/vault_cli import-backup \
  --db ./data/fuxipass.vault.db \
  --in /path/to/fuxipass-backup-YYYYMMDD.json
```

依次会提示：
1. **设置本机主密码**（可以是新的，也可以与旧机相同；建议不同）
2. **输入备份口令**（导出时设的那个）
3. 打印**恢复密钥** → **请抄下来离线保存**

> 若更简单，也可直接拷贝旧机器的 `fuxipass.vault.db` 到 `./data/`（同样加密）。

## 3. 启动网页端

```bash
./bin/vault_web --db ./data/fuxipass.vault.db
```

浏览器打开 **http://127.0.0.1:8787** ，用主密码解锁。

常用参数：
- `--port 8888` 换端口
- `--idle-timeout 900` 空闲 15 分钟自动锁定（默认 300 秒）
- `--recovery-service http://127.0.0.1:8799` 启用邮箱绑定（需另行启动找回服务）

## 4. （可选）从其他设备访问

**推荐：SSH 隧道（加密，无需改配置）**

在**你操作的那台设备**上执行：
```bash
ssh -L 8787:127.0.0.1:8787 用户名@目标机地址 -N
```
然后本机浏览器访问 http://127.0.0.1:8787 。

> ⚠️ **不要**把服务直接暴露到公网/局域网明文 HTTP：网页端是 http，
> 主密码会以明文传输。SSH 隧道已经把链路加密，是更安全的做法。

## 5. （可选）启动找回服务

```bash
./bin/recovery_service --port 8799          # 默认不开回显；本地联调可加 --dev-echo-code
```
再用 `--recovery-service` 启动网页端即可在「设置」里绑定邮箱。

## 6. 日常维护

```bash
# 备份（务必定期做）
./bin/vault_cli export --db ./data/fuxipass.vault.db --out ~/backup-$(date +%Y%m%d).json

# 改主密码
./bin/vault_cli change-password --db ./data/fuxipass.vault.db

# 忘记主密码 → 用恢复密钥重置
./bin/vault_cli recover --db ./data/fuxipass.vault.db

# 列表 / 删除
./bin/vault_cli list   --db ./data/fuxipass.vault.db
./bin/vault_cli delete --db ./data/fuxipass.vault.db --app 12306
```

## 7. 安全注意事项

1. `data/` 目录权限设为 `700`，仅本人可访问。
2. **不要**把 `data/` 放进网盘/同步目录。
3. 恢复密钥、备份口令请离线保存。
4. 用完 `Ctrl+C` 停止服务（另有空闲 5 分钟自动锁定兜底）。

## 附：目标机 glibc 过旧时（从源码构建）

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # 安装 Rust
git clone git@github.com:Yangjijun1992/FuxiPass.git && cd FuxiPass
cargo build --release
# 之后用 target/release/ 下的二进制，路径替换上面的 ./bin/
```
GUIDE

echo "==> 4/4 打包"
(cd "$OUT_BASE" && tar -czf fuxipass-deploy.tar.gz fuxipass-deploy)

echo
echo "✅ 完成"
echo "   目录: $PKG"
echo "   压缩包: $OUT_BASE/fuxipass-deploy.tar.gz"
echo
echo "下一步：把压缩包拷到目标电脑，按包内『部署步骤.md』执行。"
echo "别忘了先在旧机器导出加密备份："
echo "   $(ls -d "$ROOT" 2>/dev/null)/target/release/vault_cli export --db <旧库> --out <备份.json>"
