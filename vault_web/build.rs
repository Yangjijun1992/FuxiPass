//! 构建脚本：把当前 git 提交号写入二进制，便于确认「页面到底是哪个版本」。

fn main() {
    let sha = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=GIT_SHA={sha}");
    // 源码变动时重新构建（保证版本号跟随）
    println!("cargo:rerun-if-changed=src/index.html");
    println!("cargo:rerun-if-changed=src/main.rs");
}
