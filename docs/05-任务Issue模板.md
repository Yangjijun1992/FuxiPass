# 安全密码管家 — 开发任务 Issue 导入模板

> **来源**：`docs/02-开发任务清单.md`（33 个任务，ID/Phase/模块/依赖/人天/验收要点）
> **用途**：一键导入 GitHub / GitLab / Youtrack / 看板。提供 **GitHub Issue Markdown 清单** 与 **通用 CSV** 两种格式，二者出自同一数据源，ID 一致。

---

## 1. GitHub Issue 清单（可直接粘贴到 GitHub，创建为一个 epic 下的一组 issue）

### 🔴 Phase 1：安全底座与本地核心（11 项）

- [ ] **T1.1** CryptoCore：Argon2id 派生 + AES-256-GCM 加解密
  - `模块`: SecurityCore | `依赖`: 无 | `估时`: 5PD | `优先级`: 🔴
  - `验收`: 8.1 — KDF 参数可配置并固化；同密钥不同数据不同 nonce
- [ ] **T1.2** KeyHierarchy：KEK/DEK/AccountKey/RecoveryKey 生成与包裹
  - `模块`: SecurityCore | `依赖`: T1.1 | `估时`: 4PD | `优先级`: 🔴
  - `验收`: 8.1 — 改主密码仅重包 DEK，不重加密全量
- [ ] **T1.3** SQLCipher 数据库接入 + 加密卡片表结构
  - `模块`: Storage | `依赖`: T1.2 | `估时`: 4PD | `优先级`: 🔴
  - `验收`: 8.1 — DB 以 DEK 加密，密文无明文片段
- [ ] **T1.4** 平台适配层：Android Keystore / iOS Keychain 存取 AccountKey
  - `模块`: PlatformAdaptor | `依赖`: T1.2 | `估时`: 5PD | `优先级`: 🔴
  - `验收`: 8.1 — AccountKey 仅存 OS 安全硬件，不进 DB
- [ ] **T1.5** AuthService：主密码解锁 + 生物识别快捷会话 + 24h 强制主密码
  - `模块`: AuthService | `依赖`: T1.2/T1.4 | `估时`: 6PD | `优先级`: 🔴
  - `验收`: 8.3 — 生物只解锁短期会话；24h 强制主密码
- [ ] **T1.6** 账号卡片模型 + CRUD（Repository）
  - `模块`: Storage/业务 | `依赖`: T1.3 | `估时`: 6PD | `优先级`: 🔴
  - `验收`: 8.3 — 增删改查正常；含字段分级
- [ ] **T1.7** UI：主界面 + 搜索 + 分类标签 + 新增/详情页
  - `模块`: UI | `依赖`: T1.6 | `估时`: 8PD | `优先级`: 🟠
  - `验收`: 8.1/8.5 — 检索 < 300ms；分类正确
- [ ] **T1.8** ClipboardService：普通字段复制 + 30s 自清空 + 多次重置
  - `模块`: 服务层 | `依赖`: T1.6 | `估时`: 4PD | `优先级`: 🟠
  - `验收`: 8.5 — 普通字段 30s 清空、可配置
- [ ] **T1.9** RecoveryService：密码提示词（本地）设置/显示
  - `模块`: RecoveryService | `依赖`: T1.2 | `估时`: 3PD | `优先级`: 🟠
  - `验收`: 8.2 — 解锁失败可显示提示词
- [ ] **T1.10** RecoveryService：本地恢复码 RecoveryKey 生成/导出/重置主密码
  - `模块`: RecoveryService | `依赖`: T1.2/T1.4 | `估时`: 5PD | `优先级`: 🔴
  - `验收`: 8.2 — 恢复码可重置主密码且旧数据完整
- [ ] **T1.11** 内存安全：敏感值专用容器 + 退出置空引用
  - `模块`: SecurityCore | `依赖`: T1.1 | `估时`: 3PD | `优先级`: 🟠
  - `验收`: 8.1/§4 — 完成即置空；不做物理清零声明

### 🟠 Phase 2：分级鉴权 / 恢复 / 智能导入（8 项）

- [ ] **T2.1** FieldProtectionService：字段分级 + 二次验证 + 会话 2min
  - `模块`: 服务层 | `依赖`: T1.6 | `估时`: 6PD | `优先级`: 🔴
  - `验收`: 8.3 — 查看/复制/编辑/导出高敏感字段均二次验证；会话超时需重验
- [ ] **T2.2** FDEK 字段级加密（高敏感字段库中即不可读）
  - `模块`: SecurityCore | `依赖`: T1.3/T2.1 | `估时`: 6PD | `优先级`: 🟠
  - `验收`: 8.3 — 未二次验证时高敏感密文解密失败
- [ ] **T2.3** 防爆破：指数退避锁定（5m→10m→20m→30m 上限）
  - `模块`: AuthService | `依赖`: T1.5 | `估时`: 4PD | `优先级`: 🔴
  - `验收`: 8.2 — 第 5 次锁 5min、退避翻倍；**绝不自动清空数据**
- [ ] **T2.4** RecoveryService：邮箱/短信验证找回（两把钥匙）
  - `模块`: RecoveryService/Remote | `依赖`: T1.10/T2.3 | `估时`: 8PD | `优先级`: 🔴
  - `验收`: 8.2 — 验证码只下发 RecoveryWrap；无 RecoveryKey 无法解包
- [ ] **T2.5** Remote：邮箱/短信校验 + RecoveryWrap 上/下发（零知识隔离）
  - `模块`: Remote | `依赖`: T2.4 | `估时`: 6PD | `优先级`: 🟠
  - `验收`: 8.2/§7 — 服务端无明文/无解密密钥；TLS 1.3 + 一次性验证码
- [ ] **T2.6** ImportService：QQ/备忘录文本解析 + 表格预览 + 校验
  - `模块`: 服务层 | `依赖`: T1.6 | `估时`: 6PD | `优先级`: 🟠
  - `验收`: 8.2/8.5 — 缺字段标红；重复账号提示
- [ ] **T2.7** 导入二次确认 + 主密码验证后批量入库 + 临时清零
  - `模块`: ImportService | `依赖`: T2.6 | `估时`: 3PD | `优先级`: 🟡
  - `验收`: 8.5 — 导入前主密码验证；完成后清空缓冲
- [ ] **T2.8** 找回/重置 UI：提示词/邮箱短信/恢复码三入口 + 高敏感交互
  - `模块`: UI | `依赖`: T2.1/T2.4 | `估时`: 6PD | `优先级`: 🟠
  - `验收`: 8.2 — 三入口齐全；交互符合 §6 示意图

### 🟡 Phase 3：智能抓取与系统集成（7 项）

- [ ] **T3.1** CaptureService：登录页识别 + 授权域白名单 + 黑名单优先级
  - `模块`: 服务层 | `依赖`: T1.3 | `估时`: 7PD | `优先级`: 🔴
  - `验收`: 8.4 — 默认关闭；仅授权域触发；黑名单优先
- [ ] **T3.2** 抓取权限说明 + 逐项授权引导（隐私政策弹窗）
  - `模块`: UI/合规 | `依赖`: T3.1 | `估时`: 3PD | `优先级`: 🟠
  - `验收`: 8.4/§7 — 首次开启需逐项同意
- [ ] **T3.3** 抓取最小化：只读表单、预览脱敏、不落盘不写日志
  - `模块`: CaptureService | `依赖`: T3.1 | `估时`: 5PD | `优先级`: 🔴
  - `验收`: 8.4 — 值仅驻留内存；预览默认 `••••`
- [ ] **T3.4** Android AutoFill / iOS Keychain AutoFill 桥接（授权域内）
  - `模块`: AutoFillBridge/Platform | `依赖`: T3.1 | `估时`: 8PD | `优先级`: 🟠
  - `验收`: 8.4 — 授权域内回填；未授权不触发
- [ ] **T3.5** PrintExportService：默认打码 + 取消打码二次确认
  - `模块`: 服务层 | `依赖`: T2.1 | `估时`: 4PD | `优先级`: 🔴
  - `验收`: 8.5 — 默认打码；取消需二次确认+警示，非永久关闭
- [ ] **T3.6** 加密备份导出 + 导入恢复（RecoveryKey/口令加密，跨设备解包）
  - `模块`: PrintExport/Storage | `依赖`: T3.5/T1.10 | `估时`: 7PD | `优先级`: 🔴
  - `验收`: 8.5/§2.3 — 可跨设备导入恢复
- [ ] **T3.7** 打印/导出二次验证 + 防截图
  - `模块`: 服务层/Platform | `依赖`: T3.5 | `估时`: 4PD | `优先级`: 🟠
  - `验收`: 8.5 — 打印/导出一律二次验证 + FLAG_SECURE

### 🟢 Phase 4：安全加固与审计（7 项）

- [ ] **T4.1** 防截图/录屏：FLAG_SECURE（Android）+ iOS 前台检测（差异化）
  - `模块`: Platform | `依赖`: T1.7/T2.8 | `估时`: 5PD | `优先级`: 🔴
  - `验收`: 8.1/§4 — 明文界面不可截图/录屏；iOS 如实告知
- [ ] **T4.2** 剪贴板强化：高敏感字段默认不写系统剪贴板 / 安全输入面板
  - `模块`: ClipboardService | `依赖`: T1.8 | `估时`: 5PD | `优先级`: 🔴
  - `验收`: 8.5 — 高敏感字段默认不落剪贴板
- [ ] **T4.3** AuditService：高敏感操作审计（时间+字段类别，不落明文）
  - `模块`: 服务层 | `依赖`: T2.1 | `估时`: 4PD | `优先级`: 🟠
  - `验收`: 8.6 — 有记录、可查询；无明文
- [ ] **T4.4** PIPL 合规：数据查看/导出/删除权 + 隐私政策 + 权限最小化
  - `模块`: 合规 | `依赖`: T1.6 | `估时`: 5PD | `优先级`: 🟠
  - `验收`: 8.6 — 配置页可查/导/删；卸载清除授权
- [ ] **T4.5** Root/Jailbreak 检测 + 降级策略
  - `模块`: Platform | `依赖`: T1.4/T1.5 | `估时`: 4PD | `优先级`: 🟡
  - `验收`: 8.6/§7.4 — 检测后提示并限制敏感功能
- [ ] **T4.6** 代码级安全审计 + 内存泄露排查 + 渗透测试
  - `模块`: QA/安全 | `依赖`: 全部 | `估时`: 8PD | `优先级`: 🔴
  - `验收`: 8.6/§10 — 无高/中危漏洞；无明文/自动清空类高危
- [ ] **T4.7** 性能与兼容性回归：解锁/检索性能、备份跨版本兼容
  - `模块`: QA | `依赖`: 全部 | `估时`: 5PD | `优先级`: 🟡
  - `验收`: 8.1 — 性能达成；跨版本备份可解

---

## 2. 通用 CSV（可导入 GitHub Issues / Jira / Youtrack / Excel）

> 表头：`ID,Title,Phase,Module,Priority,Est(PD),Depends_On,Acceptance(PRD)`

```csv
ID,Title,Phase,Module,Priority,Est(PD),Depends_On,Acceptance(PRD)
T1.1,CryptoCore: Argon2id 派生 + AES-256-GCM 加解密,1,SecurityCore,P0,5,,8.1
T1.2,KeyHierarchy: KEK/DEK/AccountKey/RecoveryKey 生成与包裹,1,SecurityCore,P0,4,T1.1,8.1
T1.3,SQLCipher 数据库接入 + 加密卡片表结构,1,Storage,P0,4,T1.2,8.1
T1.4,平台适配层: Android Keystore/iOS Keychain 存取 AccountKey,1,PlatformAdaptor,P0,5,T1.2,8.1
T1.5,AuthService: 主密码解锁 + 生物识别会话 + 24h 强制主密码,1,AuthService,P0,6,T1.2;T1.4,8.3
T1.6,账号卡片模型 + CRUD (Repository),1,Storage/业务,P0,6,T1.3,8.3
T1.7,UI: 主界面 + 搜索 + 分类标签 + 新增/详情页,1,UI,P1,8,T1.6,8.1;8.5
T1.8,ClipboardService: 普通字段复制 + 30s 自清空 + 多次重置,1,服务层,P1,4,T1.6,8.5
T1.9,RecoveryService: 密码提示词(本地) 设置/显示,1,RecoveryService,P1,3,T1.2,8.2
T1.10,RecoveryService: 本地恢复码 RecoveryKey 生成/导出/重置主密码,1,RecoveryService,P0,5,T1.2;T1.4,8.2
T1.11,内存安全: 敏感值专用容器 + 退出置空引用,1,SecurityCore,P1,3,T1.1,8.1
T2.1,FieldProtectionService: 字段分级 + 二次验证 + 会话 2min,2,服务层,P0,6,T1.6,8.3
T2.2,FDEK 字段级加密(高敏感字段库中即不可读),2,SecurityCore,P1,6,T1.3;T2.1,8.3
T2.3,防爆破: 指数退避锁定(5m→10m→20m→30m),2,AuthService,P0,4,T1.5,8.2
T2.4,RecoveryService: 邮箱/短信验证找回(两把钥匙),2,RecoveryService/Remote,P0,8,T1.10;T2.3,8.2
T2.5,Remote: 邮箱/短信校验 + RecoveryWrap 上下发(零知识),2,Remote,P1,6,T2.4,8.2
T2.6,ImportService: QQ/备忘录文本解析 + 预览 + 校验,2,服务层,P1,6,T1.6,8.2;8.5
T2.7,导入二次确认 + 主密码验证后入库 + 临时清零,2,ImportService,P2,3,T2.6,8.5
T2.8,找回/重置 UI: 三入口 + 高敏感交互,2,UI,P1,6,T2.1;T2.4,8.2
T3.1,CaptureService: 登录页识别 + 授权域 + 黑名单优先级,3,服务层,P0,7,T1.3,8.4
T3.2,抓取权限说明 + 逐项授权引导(隐私弹窗),3,UI/合规,P1,3,T3.1,8.4
T3.3,抓取最小化: 只读表单/预览脱敏/不落盘不写日志,3,CaptureService,P0,5,T3.1,8.4
T3.4,Android AutoFill / iOS Keychain AutoFill 桥接,3,AutoFillBridge/Platform,P1,8,T3.1,8.4
T3.5,PrintExportService: 默认打码 + 取消打码二次确认,3,服务层,P0,4,T2.1,8.5
T3.6,加密备份导出 + 导入恢复(跨设备解包),3,PrintExport/Storage,P0,7,T3.5;T1.10,8.5
T3.7,打印/导出二次验证 + 防截图,3,服务层/Platform,P1,4,T3.5,8.5
T4.1,防截图/录屏: FLAG_SECURE + iOS 前台检测(差异化),4,Platform,P0,5,T1.7;T2.8,8.1
T4.2,剪贴板强化: 高敏感默认不写系统剪贴板,4,ClipboardService,P0,5,T1.8,8.5
T4.3,AuditService: 高敏感操作审计(不落明文),4,服务层,P1,4,T2.1,8.6
T4.4,PIPL 合规: 数据查看/导出/删除权 + 权限最小化,4,合规,P1,5,T1.6,8.6
T4.5,Root/Jailbreak 检测 + 降级策略,4,Platform,P2,4,T1.4;T1.5,8.6
T4.6,代码级安全审计 + 内存泄露排查 + 渗透测试,4,QA/安全,P0,8,ALL,8.6
T4.7,性能与兼容性回归: 解锁/检索/备份跨版本,4,QA,P2,5,ALL,8.1
```

> 说明：`Priority` 列已把文档中的 🔴🟠🟡 映射为 P0/P1/P2。

---

## 3. 使用建议

1. **GitHub**：把第 1 节粘贴到父 Epic 描述；或逐个创建 Issue（`ID + 标题` 作标题，`模块/依赖/估时/验收` 作标签与正文）。
2. **标签规范**：`phase/<1..4>`、`prio/<P0|P1|P2>`、`module/<模块>`、`acc/<8.x>`。
3. **看板列**：Backlog → To Do(依赖项完成) → In Progress → Review(验收通过) → Done。
4. **任务完成判定**：**必须**通过 `03-验收测试用例清单.md` 中的对应测试用例，否则不得标 Done。

---

*文档结束 — 任务 Issue 导入模板 V1.0*
