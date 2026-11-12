# 更新日志 (Changelog)

本项目遵循 [Semantic Versioning (语义化版本)](https://semver.org/) 规范。

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
