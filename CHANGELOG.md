# 更新日志 (Changelog)

本项目遵循 [Semantic Versioning (语义化版本)](https://semver.org/) 规范。

---

## [Unreleased]

### 🏷️ 屏幕文本实体抽取：把一串文字变成可点击的区间 (On-device NER)

- **新入口 `AauEntityExtractor`**（`:aau-ner`，LiteRT）：把调用方给的文本映射成实体区间，
  覆盖 27 类 —— 人名、电话、书面/口语地址、行政区划、公司、机构、政府、学校、医院、餐厅、酒店、
  商超、银行、银行卡号、快递单号、航班号、车次、地铁站、公交站、机场/火车站、加油站。
  返回**字符偏移**（半开区间）与原文切片，可以直接回切做点击、高亮或后续动作。
- **模型取自 `com.oplus.aiunit`**（`engine-nlp_ner_information_intent` 3.0.6）：1.3MB、字符级、
  双向 LSTM。实测一句中文 **25ms**（PLK110 / Android 17，512 字符窗口，CPU 双线程）。
- **不给置信度**：argmax 已经烘进图里，输出就是标签 id。KDoc 与 README 都写明这一点，
  免得上层拿它去调阈值。
- **长文本按 512 字符切窗**，切点优先落在后 1/4 的空白处，偏移始终相对调用方传入的原串。
- **分词表由资产驱动**：空格必须走 `[SPACE]`（词表里没有字面空格；验证时把它当 `[UNK]`
  会让「北京 朝阳区 望京SOHO」只认出「望京」），未登录字和代理对的一半都落到 `[UNK]`。
- **两个后端限制写进代码，不写在文档里**：
  - `MNNConvert` 拒绝这张图的 `REVERSE_V2`，没有 MNN 产物可加载，所以 NER 固定单后端，
    不参与 `-PaauVisionBackend` 的切换；
  - LiteRT 新的 `CompiledModel` 拒绝 variable tensor（LSTM 权重就是这么存的，`model_load.cc`
    报 `Variable tensors not yet supported`），所以走同一 AAR 里的 TFLite 兼容 `Interpreter`。
- **独立成模块 `:aau-ner`**：不再随 `:aau-vision` 的可选后端开关进出构建，也不再把
  `EntitySpan` / `EntityType` 混在图标检测的包里。LiteRT 的 Java 边界提取为 `:aau-litert`，
  图标和文本共用；该模块刻意保持纯 Java，避免 LiteRT 的 Kotlin 2.4 metadata 进入宿主编译类路径。
  代价是常驻包体：`libLiteRt.so` arm64 约 5.6MB，模型 1.3MB。
- **模型资产不入库**：权重属于 OPPO，已加入 `.gitignore`；`aau-ner/tools/import_ner_assets.py`
  从解包目录校验后安装（词表 id 连续、`[PAD]`=0、BIOES 标签、flatbuffer 头），
  词表或标签变了在导入期就失败，而不是到设备上悄悄输出乱码。
- **测试**：15 条 JVM 用例覆盖分词、切窗、BIOES 解码（孤立 I/E、类型切换、越界 id）；
  6 条真机用例跑真模型（含跨窗口偏移、同一解释器重复调用一致、耗时护栏）；未安装资产时自动跳过。

---

## [0.4.0] - 2026-11-19

### 🔓 安全图层抓取：FLAG_SECURE 页面也能出图 (Secure Layer Capture)

- **新增第五通道 `SECURE_PRIVILEGED`**：Android 17 把「是否放行安全内容」从隐式屏蔽改成了
  显式策略 —— `android.window.ScreenCapture.capture()` 接受 `SECURE_CONTENT_POLICY_CAPTURE /
  REDACT / THROW_EXCEPTION`。系统默认 `REDACT`，也就是 `screencap` 拿到的那片黑；
  显式要求 `CAPTURE` 就能拿到真实像素。
  **不需要 Root**，UID 2000 守护进程直接可用，不改系统文件、不装 Magisk 模块、不 hook
  SurfaceFlinger、不需要 LSPosed。
- **不是新链路，是 `SHELL_PRIVILEGED` 的升级分支**：`capturePng` 内部把「抓到纯黑」与
  「根本没抓到」拆成两种结果（`Attempt.Blank` / `Attempt.Failed`），只有前者才升级到
  secure 通道。普通页面零额外开销；纯黑也不再去回退 `su`——`su` 跑的仍是同一份 `screencap`，
  secure 语义在 SurfaceFlinger 层，提权不改变结果。
- **新文件 `SecureCapture.kt`**，三个实现坑都写在类注释里：
  - `compileSdk = 36` 而目标类是 API 37，**整套调用只能反射**，这反而保证了低版本安全退化；
  - 裸 `app_process` 里 `ApplicationSharedMemory` 未初始化，`capture()` 会在
    `WindowManagerGlobal.getWindowManagerService()` 抛 `IllegalStateException`。
    解法是反射往 `sWindowManagerService` 私有静态字段塞一个真 WMS 代理；
  - 回调靠 Looper 投递，调用线程若无 Looper 且阻塞等待，进程会被看门狗 SIGKILL
    （只剩一句 `Killed`，没有堆栈）。改用专用 `HandlerThread` 承载调用，调用方在外部等 latch。
- **修正纯黑帧判定阈值（`BLANK_PNG_BYTES` 12KB → 200KB）**：
  带状态栏的 FLAG_SECURE 页面实测仍有 **35441 字节**，旧阈值让它直接跳过检测，
  上层拿到的是一张「看似成功」的黑图 —— 这是最难排查的一类失败。
  现在按 200KB 放行上限 + 降采样抽检（约 860 点，1~2ms），复杂页面（实测 148KB~3MB）不误伤。
- **长截图自动粘住 secure 通道**：某一帧确认走 secure 后，后续帧直接沿用
  （`ShellFrameSource.secureSticky`），避免每帧先跑一次注定要丢掉的 `screencap`。
- **能力快照扩展 `secureCaptureAvailable`**：`ScreenCaptureCapability` 新增字段与 Bundle 键，
  并补 `canCaptureAnyContent`（普通页面 + 安全页面都能抓）。
- **诊断项 `secure_layer_capture`**：`AAUDiagnosticSuite` 里显式回答「这台机器能不能抓
  FLAG_SECURE 页面」，不可用时提示改走无障碍节点树。
- **自检入口 `CaptureSelfCheck`**：`app_process ... com.agent.use.server.CaptureSelfCheck
  <outDir> [AUTO|SHELL|ROOT|SECURE|NOSECURE]`，绕开 Provider 握手单独验证截屏链路。
- **真机实测（PLK110 / Android 17 / ColorOS，FLAG_SECURE 靶子页）**：

| 路径 | 结果 | 字节 | 耗时 |
|---|---|---|---|
| `AUTO`（生产路径） | 自动升级，mode=secure | 150407 | 557ms |
| `SECURE`（强制） | mode=secure | 146488 | 422ms |
| `NOSECURE`（禁止升级） | 失败，reason=纯黑（FLAG_SECURE） | — | 503ms |
| 普通桌面 `AUTO` | mode=shell，未触发升级 | 3113016 | 1909ms |

- **未突破的边界**：DRM protected buffer（Widevine L1 等）在 DPU 安全通路里解密，
  非 secure 输出拿不到明文；抓到仍是纯黑时按失败返回，不谎报成功。

---

## [0.3.0] - 2026-11-18

### 📸 免授权截屏与滚动长截图 (Privileged Screen Capture)

- **`screencap` 特权通道**：守护进程本身运行在 Shell (UID 2000)，`screencap -p -d <displayId>` 对它是免授权的，
  因此抓主屏不再需要 `MediaProjection` 的「开始录制」弹窗，也不再要求用户开启无障碍；
  个别 OEM 把 `screencap` 限死在 UID 0 时，按 `AUTO` 策略经 `su -c` 自动重试一次。
- **多通道降级调度 `ScreenCaptureChannel`**：
  `VIRTUAL_DISPLAY`（ImageReader 直读） → `SHELL_PRIVILEGED` → `ROOT_PRIVILEGED` → `ACCESSIBILITY`，
  逐条尝试并记录 `CaptureAttempt`，调用方拿到的不只是图，还有「实际走了哪条通道」。
- **滚动拼接长截图 `LongScreenshotRunner`**：
  - **行特征 `RowSignature`**：每行横向等分 8 段取平均灰度，打包进一个 `Long`；
    刻意降维，因为长截图需要的是**可度量的距离**，而不是高熵哈希（见下方「真机纠偏」）；
  - **`OverlapFinder` 锚点投票**：从新帧挑高纹理行当锚点，各自在旧帧找最像的位置，
    对 `delta = j - i` 投票，票数最高的几个再用整段加权距离复核；
  - **两段式等待稳定**：`input swipe` 后有惯性滑行与 overscroll 回弹，
    必须等到「画面已变且连续两帧相似」才取帧，否则会抓到反向位移；
  - 顶部固定标题栏/底部固定栏可排除（`topInsetRatio` / `bottomInsetRatio`）；
  - 终止原因显式化：`REACHED_END` / `NO_OVERLAP` / `MAX_HEIGHT` / `MAX_SCROLLS` / `NO_PROGRESS` / `CAPTURE_FAILED`；
  - 倍增扩容画布，避免为一次两屏截图预分配 12000 行（约 51 MB）。
- **真机纠偏（PLK110 / Android 17），三处算法与参数被推翻重写**：
  - `screencap -d` 的 id 命名空间变了：只认 **PhysicalDisplayId**（64 位，如 `4630946903293830803`），
    传逻辑 id `0` 直接报 `Display Id '0' is not valid`。引擎改为「主屏不传 `-d`、非主屏解析
    `dumpsys SurfaceFlinger --display-id` 换算」，且解析不到时**明确失败**而不是退化抓主屏；
  - 虚拟屏没有物理 id，`screencap` 抓不到——这条通道只服务物理屏，虚拟屏仍走 ImageReader；
  - KMP 精确匹配在真机上归零（一次滚动仅约 97.8% 行逐像素相同），「粗扫 + 局部精修」同样失效
    （真实位移不落在步长上时谷底只有一两行宽），最终改为锚点投票；
  - 滚动默认值从 58% 屏高/280ms 收到 **30% 屏高/900ms**：`input swipe` 的 fling 惯性会把实际位移
    推到手势距离的 1.5~1.8 倍，重叠不足时锚点投票必然失效；
  - 首帧与后续帧可能不同源：可折叠大标题在第一次滚动时收起，内容原点整体上移一两百像素，
    此时以稳定后的帧为新起点重启拼接（`LongScreenshotStitcher.reset()`）。
- **端到端实测**：设置页 4 帧拼成 1272×6147，24 个条目完整、无重复、无跳过，耗时约 13.6s。
- **Binder 交付不走事务缓冲区**：服务端把 PNG 写入私有目录后 **打开 fd 并立即 unlink**，
  客户端从只读 fd 流式读取。既绕开 1 MB 的 `TransactionTooLargeException`，
  也不会把用户屏幕内容留在设备上（`/data/local/tmp` 归 shell 所有，传路径给应用必然 EACCES）。
- **新增 3 个 AIDL 事务**（55~57）：`capturePng` / `captureLongPng` / `captureCapability`，
  并新增 `LongScreenshotOptions` Parcelable 契约与 `ScreenCaptureCapability` 能力快照。
- **安全图层显式化**：`FLAG_SECURE` 页面 `screencap` 会返回纯黑而非失败，
  引擎对「压缩后异常小」的 PNG 做一次抽样判定，把黑屏作为失败上报，而不是让上层拿到一张「看似成功」的黑图。
- **无障碍兜底长截图**：`AgentAccessibilityService.captureLongScreenshot` 复用同一套拼接算法，
  默认参数针对 `takeScreenshot` 的 1 秒系统冷却调整为 1.1 秒稳定等待，避免每帧双倍等待。
- **单测覆盖**：`LongScreenshotCaptureTest` 以合成行特征锁定 13 个边界（正常滚动、带噪声匹配、
  噪声超限拒绝、到底、整屏换掉、阈值拒绝、固定标题栏、底栏、纯色页面、高度不一致、参数裁剪、
  相似度判定）。合成数据用 splitmix64 生成——线性映射与 LCG 都会让「无关位移」只产生固定小差值，
  把测试变成测生成器的漏洞。

---

## [0.2.0] - 2026-11-12

### 🚀 统一模块命名与包名重构 (AAU Modernization)
- **模块目录重命名**：全面由 `agent-display-*` 迁移至 `aau-*` 标准风格：
  - `aau-common`: 核心契约与顶层门面
  - `aau-server`: 特权服务端守护进程（输出 `aau-server.jar`）
  - `aau-client`: 客户端 SDK 与 CDP 网络管理器
  - `aau-a11y`: 无障碍语义树与手势交互
  - `aau-setup`: 特权引导与诊断套件
- **根包名空间统一**：全面迁移至 `com.agent.use.*`（Maven Group 统一为 `com.agent.use`）；
- **门面与类重命名**：
  - `AgentDisplayManager` 升级为 `AAUManager`（保留 `@Deprecated typealias` 向后兼容）；
  - `AgentDisplayDiagnosticSuite` 升级为 `AAUDiagnosticSuite`（保留 `@Deprecated typealias` 向后兼容）。

### 🌐 原生 CDP 风格网络嗅探与流量捕获子系统 (Native Network Capture)
- **多态双模抓包引擎**：
  - **Root eBPF 引擎**：在 Linux 内核 5.4+ (GKI) 上基于 Conscrypt/BoringSSL uprobe 挂载，实现 100% 零证书、零注入 HTTPS 明文捕获；内核态严格匹配 `targetUid`，保证宿主应用零干扰；内置 HTTP/1.1 与 HTTP/2 RFC 7541 HPACK 解析器；
  - **非 Root 局部 VpnService 引擎**：基于 `addAllowedApplication(targetPackage)` 局部隔离，宿主应用完全旁路直连；内置 TUN 报文解码器（IPv4/IPv6/TCP/UDP/DNS/TLS SNI/HTTP）；
- **客户端高层门面 `AgentNetworkManager`**：
  - `CaptureMode.AUTO` 智能自适应调度与优雅降级；
  - CDP 风格 API：`waitForResponse`（具备 200ms 防先发竞态时间窗口）、`requestFlow`、`responseFlow`、`onRequest` 与 `onResponse`；
  - 深度集成 `DisplaySession` 与 Jetpack Lifecycle。

---

## [0.1.0] - 2026-11-12

### 🎉 首个开源正式版本 (Initial Release)

Android Agent Use (AAU) 正式发布！AAU 是专为移动端 AI Agent 打造的纯净、零扰民、高性能的 Android 虚拟屏运行环境与自动化控制工具包。

### 🚀 核心架构与模块特性

#### 1. agent-display-common (公共契约层)
- **标准跨进程协议**：定义通用 `IAgentShell.aidl`，提炼 49 项高内聚原子方法，彻底剥离特定宿主私有逻辑；
- **通用数据契约**：
  - `DisplayConfig`：Parcelable 屏幕配置，支持 Android 12~15 特权标志位推导与安全降级；
  - `DisplayGeometry`：底层物理缓冲与逻辑坐标双向映射算法（`mapLogicalToBuffer` / `mapBufferToLogical`）；
  - `LaunchResult`：9 项完备启动状态机枚举（涵盖主屏防扰避让、冷启动转热启动等）；
  - `AudioMode`：AppOps 音频控制规范，包含安全的默认还原写回机制（强制写回 `allow`）；
  - `TaskSnapshotInfo`, `FinishDisplayResult`, `CommandResult`, `MainArrivalsResult` 等结构化模型；
- **上层 API 外观**：提供面向第三方的简洁面向对象门面 `AgentDisplayManager` 与 `AgentVirtualDisplay`。

#### 2. agent-display-server (特权服务端)
- **Shell UID 2000 守护进程**：独立脱钩运行，不受客户端进程生命周期崩溃影响；
- **VirtualDisplay 特权构建**：
  - 支持 Android 13+ `FLAG_OWN_DISPLAY_GROUP` 独立显示组与 `FLAG_ALWAYS_UNLOCKED`；
  - 支持 Android 14+ `FLAG_STEAL_TOP_FOCUS_DISABLED` 与 `FLAG_OWN_FOCUS` 核心焦点隔离；
  - 支持 `SecurityException`（缺少 `ADD_TRUSTED_DISPLAY`）自动无感降级；
- **系统窗口与输入法隔离**：强制全屏模式 (`WINDOWING_MODE_FULLSCREEN=1`) 与本地输入法隔离 (`DISPLAY_IME_POLICY_LOCAL=0`)；
- **动态转屏纠偏**：`DisplayOrientationWatcher` 动态挂载 `ITaskStackListener` 监听 Activity 旋转并自动纠偏，失败平稳降级轮询；
- **输入精准注入**：自适应 API 34+ `InputManagerGlobal` 与标准 `InputManager`，支持单指平滑手势、按键与 ASCII 纯文本投递；
- **音频持久化账本**：`AudioMuteLedger` 记录被静音应用原模式，服务重启与退出时全量安全还原。

#### 3. agent-display-client (客户端 SDK)
- **高性能直读图像管线**：基于 `ImageReader` RGBA_8888 双缓冲直读，无中间内存二次拷贝；
- **≤10fps 动态限速丢帧队列**：100ms 动态节流与 `acquireLatestImage()` 丢帧保护，CPU/GPU 占用极低；
- **反向旋转校正**：单次 Canvas 中完成行填充裁剪、旋转校正与等比缩放；提供 `frames` (StateFlow)、Bitmap、PNG 格式抽取；
- **主屏防扰与自动回捞**：`MainScreenConflictManager` 在动作前后实施主屏监控，检测并自动调用 `moveTask` 将意外溢出应用回捞至虚拟屏；
- **开屏防爆音与静音调度**：`AgentAudioManager` 启动前预静音，启动异常即时还原；
- **面向对象资源池**：`AgentDisplayPool` 自动复用，`DisplaySession` 深度集成 `AutoCloseable` 与 Jetpack Lifecycle。

#### 4. agent-display-a11y (无障碍扩展插件)
- **屏幕定向语义解析**：`DisplayWindowInspector` 过滤虚拟屏顶层窗口，安全转换为不可变 `A11yNode` 语法树，严格调用 `recycle()` 杜绝内存泄露；
- **协程手势下发**：`DisplayGestureDispatcher` 挂载 `suspendCancellableCoroutine`，支持单点、连击、长按与平滑手势分发；
- **环形防背压事件总线**：`DisplayEventStream` 提供按屏过滤的事件路由。

#### 5. agent-display-setup (特权引导与诊断套件)
- **四级特权降级引导**：`PrivilegeManager` 编排 Shizuku 秒启 ➔ 本地无线调试 mDNS 发现 ➔ Root 降权运行 ➔ USB 引导；
- **安全降权规范**：Root 启动显式执行 `su 2000 -c`，确保与 ADB 上下文完全一致；
- **全链路诊断套件**：`AgentDisplayDiagnosticSuite` 覆盖 6 项静态环境检查与 6 项动态硬件/特权闭环探测，输出不可变报告 `DiagnosticReport`。
