# agent-display-common 模块规范与数据契约

`agent-display-common` 是 **AgentDisplayKit** 虚拟屏解耦与通用化工具包的核心契约层。它统一定义了跨进程通信 AIDL 接口规范、通用数据结构模型以及提供给第三方 Agent 开发者的上层面向对象 Kotlin API 外观。

---

## 1. 架构定位与模块职责

```
┌────────────────────────────────────────────────────────┐
│               Third-Party Agent Application            │
│  (AgentDisplayManager / AgentVirtualDisplay / Flows)   │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│                  agent-display-client                  │
│       (ImageReader 零拷贝直读 / ≤10fps 动态限速丢帧队列)       │
└───────────────────────────┬────────────────────────────┘
                            │ Binder (IAgentShell.aidl)
┌───────────────────────────▼────────────────────────────┐
│                  agent-display-common                  │
│    (IAgentShell.aidl / DisplayConfig / LaunchResult)   │
└───────────────────────────┬────────────────────────────┘
                            │ IPC
┌───────────────────────────▼────────────────────────────┐
│                  agent-display-server                  │
│     (Shell UID 2000 独立守护进程 / VirtualDisplay / AppOps)   │
└────────────────────────────────────────────────────────┘
```

- **面向客户端**：为 `agent-display-client` 提供轻量强类型的纯 Kotlin 运行时外观与响应式流支持。
- **面向服务端**：为 `agent-display-server` 提供无业务污染的精炼 AIDL 规范与参数 Parcelable 定义。
- **面向第三方开发者**：屏蔽底层 AIDL Binder 繁琐细节，提供简单易用的现代 Kotlin 接口。

---

## 2. 接口设计：IMikaShell 到 IAgentShell 的演进

深入比对 Mika 历史版本 `IMikaShell.aidl`（51个方法），彻底剥离了 Mika 私有业务，提炼出面向通用 Agent 的 **49 个精炼原子接口**：

| 分类 | 接口定义 (IAgentShell.aidl) | 剥离/保留理由 |
| :--- | :--- | :--- |
| **虚拟屏生命周期** | `createDisplay(Surface, DisplayConfig): int`<br>`releaseDisplay(int): void`<br>`releaseAll(): void`<br>`destroy(): void` | **保留并升级**：将分散的 width/height/dpi/flags 聚合为 `DisplayConfig` Parcelable，支持动态配置；支持全量释放与守护进程自毁。 |
| **应用与任务调度** | `startApp(int, String): int`<br>`restartApp(int, String): int`<br>`startAppInUser(int, String, int, boolean): int`<br>`startIntent(int, Intent): int`<br>`startView(int, String, String, String): int`<br>`startShare(int, String, String): int`<br>`finishDisplay(int, String[], String[]): Bundle` | **剥离 Mika 专属**：剔除带有 Mika 专属权限的 `startSystemAction(..., PendingIntent asMika)` 和闹钟/日历白名单，抽象为通用的 `startIntent`；保留主屏避让与多用户支持。 |
| **任务层级查询** | `topTaskId(int): int`<br>`topActivity(int): String`<br>`packageOfTask(int): String`<br>`displayOfTask(int): int`<br>`displayOfPackage(String): int`<br>`displayOfPackageInUser(String, int): int`<br>`userOfTask(int): int`<br>`moveTask(int, int): boolean` | **完备保留**：提供跨屏幕任务识别与平滑迁移（moveTask）机制，供客户端实现任务自动回捞。 |
| **主屏冲突避让** | `visibleOnMainScreen(String, int): boolean`<br>`watchMainScreen(int): int`<br>`mainArrivals(long): Bundle` | **核心保留**：普通 App 缺乏 `REAL_GET_TASKS` 权限，底层必须由 Shell 监控主屏任务并感知后台溢出弹窗。 |
| **输入事件注入** | `injectTap(int, int, int): boolean`<br>`injectStroke(int, int[], int[], long[]): boolean`<br>`injectKey(int, int): boolean`<br>`injectCtrlKey(int, int): int`<br>`injectAsciiText(int, int, String, String): int` | **完备保留**：支持单指平滑轨迹、组合键 (Ctrl+A/V) 及针对前台任务的 ASCII 键盘直投。 |
| **音频与 AppOps** | `setAudioMuted(String, boolean): boolean`<br>`getAudioMode(String): String`<br>`setAudioMode(String, String): boolean`<br>`setAudioMutedInUser(...)` / `getAudioModeInUser(...)` | **完备保留**：基于 AppOps PLAY_AUDIO 实现虚拟屏静音，杜绝后台爆音；支持分身多用户。 |
| **剪贴板隔离** | `setClipText(String): int`<br>`restoreClip(): boolean`<br>`savedClipText(): String`<br>`restoreClipText(String, String): boolean` | **完备保留**：带 `SUPPRESS_CLIPBOARD_OVERLAY`（不弹主屏已复制提示）与敏感标记。 |
| **设备解锁与准备** | `wakeDevice(): boolean`<br>`dismissDeviceKeyguard(): boolean`<br>`revealDeviceCredential(): boolean`<br>`revealDeviceCredentialTap(int, int): boolean`<br>`enterDeviceCredential(int, byte[], int): boolean` | **完备保留**：提供无密码锁屏唤醒与安全的 Binder 凭据解锁通道（不写 shell 命令行）。 |
| **系统特权执行** | `identity(): int[]`<br>`runCommand(String): Bundle`<br>`runSystemCommand(int, String): Bundle` | **完备保留**：用于环境探测与注入 `AGENT_DISPLAY_ID` 的上下文命令执行。 |
| **剔除的 Mika 特性** | `openDevtoolsSocket(String)`<br>`setRestoreWish(int)`<br>`startSystemAction(..., asMika)` | **彻底移除**：Mika 专属 WebView DevTools 抽象套接字、Mika 崩溃心愿拉起机制、教导模式及专属页面。 |

---

## 3. 核心数据契约设计

### 3.1 DisplayConfig (Parcelable)
```kotlin
data class DisplayConfig(
    val width: Int,
    val height: Int,
    val dpi: Int,
    val flags: Int = 0,
    val name: String = "agent-virtual-display"
) : Parcelable
```
- 内置标准预设：`standard1080p()`、`compact720p()`、`tablet()`。
- 动态 Flags 计算：`resolveRecommendedFlags(sdk, trusted)` 自动适配 Android 12-15：
  - Android 13: `FLAG_TOUCH_FEEDBACK_DISABLED`, `FLAG_OWN_DISPLAY_GROUP`, `FLAG_ALWAYS_UNLOCKED`
  - Android 14+: `FLAG_OWN_FOCUS`, `FLAG_STEAL_TOP_FOCUS_DISABLED`（核心焦点隔离）

### 3.2 DisplayGeometry
```kotlin
data class DisplayGeometry(
    val bufferWidth: Int,
    val bufferHeight: Int,
    val rotation: Int = Surface.ROTATION_0
)
```
- 计算逻辑宽高（横竖屏切换时反向调换）。
- 坐标双向映射：`mapLogicalToBuffer` / `mapBufferToLogical`。
- 预览自适应缩放：`calculatePreviewSize` / `previewWidth(shortSide)`。

### 3.3 LaunchResult (Enum)
- 映射所有启动状态：
  - `SUCCESS (0)`: 启动成功
  - `IN_USE_ON_MAIN (1)`: 主屏可见，避让中断
  - `NOT_FOUND (2)`: 未找到入口
  - `ERROR (3)`: 底层异常
  - `COLD_IGNORED_WARM_STARTED (4)`: 冷启动转热启动
  - `UNRESOLVED_INTENT (5)`: 无法解析的 Intent
  - `INVALID_LINK (6)`: 链接被拦截
  - `IN_USE_BY_OTHER_DISPLAY (7)`: 其他虚拟屏占用
  - `USER_NOT_ALLOWED (8)`: 用户权限受限
- 辅助方法：`isSuccess`、`isConflict`。

### 3.4 AudioMode & AppAudioKey
- `AudioMode`: `ALLOW`, `IGNORE`, `DENY`, `DEFAULT`。
- 关键安全恢复机制：`calculateRestoreMode(prior)` 针对系统默认状态必须写回 `allow`，避免出现应用永久无声的系统脏状态。
- `AppAudioKey`: 统一单用户与分身多用户标识（`packageName@userId`）。

---

## 4. 开发者 API 外观 (AgentDisplayManager & AgentVirtualDisplay)

### 快速接入示例：
```kotlin
// 1. 初始化 Manager (支持 Binder 链接与断线监听)
val manager = AgentDisplayManager.fromBinder(context, shellBinder)

// 2. 创建并持有一块虚拟屏
val display = manager.createVirtualDisplay(DisplayConfig.standard1080p())

// 3. 响应式流预览 (已做反向旋转校正与 ≤10fps 动态限速)
lifecycleScope.launch {
    display.frames.collect { frameBitmap ->
        previewView.setImageBitmap(frameBitmap)
    }
}

// 4. 启动应用并操作
val result = display.startApp("com.example.app")
if (result.isSuccess) {
    // 注入触摸手势
    display.injectTap(540, 1200)
    display.injectAsciiText("Hello Agent")
    display.injectKey(KeyEvent.KEYCODE_ENTER)
}

// 5. 高性能截图 (供大模型 OCR 或视觉理解)
val pngBytes: ByteArray? = display.latestPng()
val rawBitmap: Bitmap? = display.latestBitmap() // 使用完毕需主动 recycle()

// 6. 安全优雅收尾 (应用沉底保活，虚拟屏安全释放)
display.finish(
    keepPackages = listOf("com.example.app"),
    closePackages = emptyList()
)
```
