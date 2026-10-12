#!/usr/bin/env bash
# FuxiPass 开发环境就绪检查（macOS / Linux 通用）
#
# 用法：bash scripts/check-dev-ready.sh
#
# 设计原则：
#   - 只读检查 + 临时目录操作，**绝不触碰正式数据库**
#   - 不联网（除编译时按需拉取依赖）、不需要 sudo、不需要 git 仓库
#   - 每步打印 ✅/❌，最后给出总结与可执行的修复建议
#
# 退出码：0 = 全部通过；1 = 有未通过项

set -u

PASS=0
FAIL=0
declare_fail_list=""

ok()   { printf '  ✅ %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  ❌ %s\n' "$1"; FAIL=$((FAIL + 1)); declare_fail_list="$declare_fail_list\n     - $1"; }
skip() { printf '  ⏭️  %s\n' "$1"; }
head1() { printf '\n[%s] %s\n' "$1" "$2"; }

TMP="$(mktemp -d 2>/dev/null || echo /tmp/fuxipass-check-$$)"
mkdir -p "$TMP"
PORT="${FUXIPASS_CHECK_PORT:-8790}"
cleanup() {
  if [ -n "${WEB_PID:-}" ]; then kill "$WEB_PID" 2>/dev/null; wait "$WEB_PID" 2>/dev/null; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

printf '========================================\n'
printf ' FuxiPass 开发环境就绪检查\n'
printf ' 主机: %s  系统: %s\n' "$(hostname)" "$(uname -s)"
printf '========================================\n'

# ── 1. 工具链 ────────────────────────────────────────────────
head1 "1/6" "工具链"

if command -v rustc >/dev/null 2>&1; then
  RUSTC_VER="$(rustc --version | awk '{print $2}')"
  MAJOR="$(printf '%s' "$RUSTC_VER" | cut -d. -f1)"
  MINOR="$(printf '%s' "$RUSTC_VER" | cut -d. -f2)"
  if [ "$MAJOR" -gt 1 ] 2>/dev/null || { [ "$MAJOR" -eq 1 ] 2>/dev/null && [ "$MINOR" -ge 75 ] 2>/dev/null; }; then
    ok "rustc $RUSTC_VER（要求 ≥ 1.75）"
  else
    bad "rustc $RUSTC_VER 过旧（要求 ≥ 1.75）→ 修复：rustup update stable"
  fi
else
  bad "未找到 rustc → 修复：curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
fi

if command -v cargo >/dev/null 2>&1; then
  ok "cargo $(cargo --version | awk '{print $2}')"
else
  bad "未找到 cargo（随 rustup 一起安装）"
fi

for comp in fmt clippy; do
  if cargo "$comp" --version >/dev/null 2>&1; then
    ok "$comp 可用"
  else
    bad "缺少 $comp → 修复：rustup component add $comp"
  fi
done

if command -v git >/dev/null 2>&1; then
  ok "git $(git --version | awk '{print $3}')"
else
  bad "未找到 git → 修复：xcode-select --install（macOS）"
fi

if [ "$(uname -s)" = "Darwin" ]; then
  if xcode-select -p >/dev/null 2>&1; then
    ok "Xcode 命令行工具已安装（$(xcode-select -p)）"
  else
    bad "未安装 Xcode 命令行工具 → 修复：xcode-select --install"
  fi
else
  skip "非 macOS，跳过 Xcode 检查"
fi

# ── 2. 编译 ──────────────────────────────────────────────────
head1 "2/6" "编译（release）"

if [ -f Cargo.toml ]; then
  ok "在项目根目录运行（找到 Cargo.toml）"
else
  bad "当前目录没有 Cargo.toml → 请在项目根目录运行本脚本"
  printf '\n%s\n' "（后续步骤无法继续）"
  printf '\n未通过项：%b\n' "$declare_fail_list"
  exit 1
fi

printf '  编译中（首次可能需要几分钟）…\n'
if cargo build --release --bin vault_web --bin vault_cli --bin recovery_service >"$TMP/build.log" 2>&1; then
  ok "三个可执行文件编译成功"
  for b in vault_web vault_cli recovery_service; do
    if [ -x "target/release/$b" ]; then ok "  生成 target/release/$b"; else bad "  缺少 target/release/$b"; fi
  done
else
  bad "编译失败 → 详见 $TMP/build.log（错误摘要如下）"
  grep -E "^error" "$TMP/build.log" 2>/dev/null | head -5 | sed 's/^/       /'
fi

# ── 3. 测试 ──────────────────────────────────────────────────
head1 "3/6" "测试套件"

printf '  运行中（首次编译测试目标可能需要几分钟）…\n'
if cargo test --workspace >"$TMP/test.log" 2>&1; then
  TOTAL="$(grep -oE '^test result: ok\. [0-9]+' "$TMP/test.log" | grep -oE '[0-9]+$' | paste -sd+ - | bc 2>/dev/null)"
  TARGETS="$(grep -cE '^test result:' "$TMP/test.log")"
  ok "全部通过：${TOTAL:-?} 项 / ${TARGETS:-?} 个测试目标"
else
  bad "有测试失败（注意：不要只看末尾，失败目标可能在中段）"
  grep -E "^test result: FAILED|^---- " "$TMP/test.log" 2>/dev/null | head -5 | sed 's/^/       /'
fi

# ── 4. 质量门禁 ──────────────────────────────────────────────
head1 "4/6" "质量门禁（与 CI 一致）"

if cargo fmt --all -- --check >/dev/null 2>&1; then
  ok "cargo fmt 通过"
else
  bad "格式不符合规范 → 修复：cargo fmt --all"
fi

if cargo clippy --all-targets -- -D warnings >"$TMP/clippy.log" 2>&1; then
  ok "cargo clippy 零警告"
else
  bad "clippy 有告警/错误 → 详见上方输出（修复后重跑）"
  grep -E "^(error|warning)" "$TMP/clippy.log" 2>/dev/null | head -3 | sed 's/^/       /'
fi

# ── 5. 运行冒烟测试（临时库，绝不碰正式数据）──────────────────
head1 "5/6" "运行冒烟测试（临时库，端口 $PORT）"

if [ -x target/release/vault_web ]; then
  target/release/vault_web --db "$TMP/smoke.vault.db" --port "$PORT" --seed-demo "readiness-test-123" \
    >"$TMP/web.log" 2>&1 &
  WEB_PID=$!
  READY=0
  i=0
  while [ "$i" -lt 15 ]; do
    sleep 1
    if curl -s --max-time 3 "http://127.0.0.1:$PORT/api/status" | grep -q '"initialized":true'; then
      READY=1
      break
    fi
    i=$((i + 1))
  done
  if [ "$READY" -eq 1 ]; then
    ok "服务可启动并响应（http://127.0.0.1:$PORT/api/status）"
    VER="$(curl -s --max-time 3 "http://127.0.0.1:$PORT/api/status" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
    ok "构建版本标识：${VER:-（未提供）}"
    if curl -s --max-time 3 "http://127.0.0.1:$PORT/" | grep -q 'recovery-result'; then
      ok "界面资源完整（含最新前端）"
    else
      bad "界面资源异常（缺少最新前端标记）"
    fi
  else
    bad "服务未能启动 → 详见 $TMP/web.log"
    tail -3 "$TMP/web.log" 2>/dev/null | sed 's/^/       /'
  fi
  kill "$WEB_PID" 2>/dev/null
  wait "$WEB_PID" 2>/dev/null
  WEB_PID=""
  ok "临时库已用完即弃（正式数据全程未被触碰）"
else
  bad "缺少 vault_web 可执行文件（编译步骤未成功）"
fi

# ── 6. 总结 ──────────────────────────────────────────────────
head1 "6/6" "总结"

printf '\n  通过：%s 项   未通过：%s 项\n' "$PASS" "$FAIL"

if [ "$FAIL" -eq 0 ]; then
  printf '\n  ✅ 这台机器已具备完整的开发与维护能力。\n'
  printf '     可以放心在本机进行后续的开发、维护与升级。\n'
  printf '\n  下一步（可选，需要 GitHub 凭据时）：\n'
  printf '     - 配置 SSH 密钥：ssh-keygen -t ed25519 -C "你的邮箱"\n'
  printf '     - 克隆仓库后即可直接开发：见 docs/10-macOS-开发与维护.md\n'
  exit 0
else
  printf '\n  ⚠️  存在未通过项：%b\n' "$declare_fail_list"
  printf '\n  按上面的“修复”提示处理后，重新运行本脚本即可。\n'
  exit 1
fi
