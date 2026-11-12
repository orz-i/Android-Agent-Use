package com.agent.use.common;

import android.content.Intent;
import android.os.Bundle;
import android.view.Surface;
import com.agent.use.common.DisplayConfig;
import com.agent.use.common.network.INetworkCapture;
import com.agent.use.common.network.INetworkCapture;

/**
 * 运行在 Shell UID 2000 / Root 进程中的通用 Agent 虚拟屏与系统服务桥接接口。
 *
 * 核心设计原则：
 * 1. 通用性：剔除特定宿主业务接口（如专属调试 Socket、特定闹钟日历白名单等），保留纯净的虚拟屏调度与输入控制能力；
 * 2. 独立性：虚拟屏在 Shell 进程持有，不受客户端 Activity 生命周期销毁影响；
 * 3. 防干扰：严格遵循主屏冲突避让，当目标应用在用户主屏可见时拒绝盲目启动；
 * 4. 稳定性：支持 Android 12 至 Android 15 定制 ROM 的权限降级与反射回退。
 */
interface IAgentShell {

    // ==========================================
    // 1. 虚拟屏生命周期管理 (Display Lifecycle)
    // ==========================================

    /**
     * 在 Shell 进程中创建独立的 VirtualDisplay，画面渲染输出到客户端传递的 Surface。
     * 服务端会依次配置全屏模式(WindowingMode=1)、IME策略(LOCAL=0)及按屏防休眠心跳。
     *
     * @param surface 客户端 ImageReader 或 SurfaceView 提供的渲染目标表面
     * @param config 包含宽高、DPI、标志位等配置信息的数据契约
     * @return 成功返回系统分配的 displayId (>= 0)，创建失败返回 -1
     */
    int createDisplay(in Surface surface, in DisplayConfig config) = 1;

    /**
     * 释放指定的虚拟屏，注销方向监听，停止该屏的防休眠唤醒心跳。
     * 屏上剩余未迁移的应用将随 FLAG_DESTROY_CONTENT_ON_REMOVAL 自动销毁。
     */
    void releaseDisplay(int displayId) = 2;

    /**
     * 释放当前 Shell 会话创建的所有虚拟屏，恢复已修改的剪贴板与音频模式。
     * 常用于客户端异常断连或主动解绑。
     */
    void releaseAll() = 3;

    /**
     * 释放所有资源并终止 Shell 守护进程 (exitProcess(0))。
     */
    void destroy() = 4;


    // ==========================================
    // 2. 应用与任务生命周期 (App & Task Lifecycle)
    // ==========================================

    /**
     * 将目标应用启动至指定的虚拟屏（当前用户）。
     * 启动前会严格检查主屏占用状态：若应用在主屏可见，则拒绝启动以防打扰用户。
     *
     * @param displayId 目标虚拟屏编号
     * @param packageName 目标应用包名
     * @return LaunchResult 对应的状态码:
     *         0: 成功 (START_OK)
     *         1: 用户在主屏使用中，拒绝启动 (START_IN_USE_ON_MAIN)
     *         2: 未找到可启动入口 (START_NOT_FOUND)
     *         3: 启动异常 (START_ERROR)
     *         7: 正在其他 Agent 虚拟屏中运行 (START_IN_USE_BY_OTHER)
     */
    int startApp(int displayId, String packageName) = 5;

    /**
     * 冷启动目标应用：仅当该应用在虚拟屏以外没有其他任务时结束进程再启动；
     * 若用户在主屏使用中则不启动；若在其他屏还有非 Agent 任务则转为普通热启动并返回 4。
     */
    int restartApp(int displayId, String packageName) = 6;

    /**
     * 在指定的多用户编号 (分身应用 / 工作资料 / 双开用户) 下启动或冷启动应用。
     *
     * @param displayId 目标虚拟屏编号
     * @param packageName 目标应用包名
     * @param userId 多用户标识 (0 为主用户)
     * @param cold 是否冷启动 (true 时先 kill 该用户下的进程)
     * @return 状态码同 startApp，另有 8: 指定用户不在可用列表中 (START_USER_NOT_ALLOWED)
     */
    int startAppInUser(int displayId, String packageName, int userId, boolean cold) = 7;

    /**
     * 通用 Intent 启动接口：将构造好的 Intent 添加 FLAG_ACTIVITY_NEW_TASK 并设置 LaunchDisplayId 启动。
     */
    int startIntent(int displayId, in Intent intent) = 8;

    /**
     * 打开安全链接、深度跳转 (DeepLink) 或系统设置页。
     *
     * @param displayId 目标虚拟屏编号
     * @param action Intent Action (为空时默认为 ACTION_VIEW)
     * @param uri 跳转目标 URI
     * @param packageName 限定接收方包名 (可选)
     * @return 状态码，另有 5: 无应用能处理 (START_UNRESOLVED), 6: 链接不安全 (START_INVALID_LINK)
     */
    int startView(int displayId, String action, String uri, String packageName) = 9;

    /**
     * 往虚拟屏内的指定应用发送文本分享 (ACTION_SEND text/plain)。
     */
    int startShare(int displayId, String packageName, String text) = 10;

    /**
     * 优雅结束虚拟屏任务：将指定保留的应用沉入主屏任务栈底（不弹出打扰用户），
     * 将正在发声或指定关闭的应用随屏销毁。
     *
     * @param displayId 虚拟屏编号
     * @param keepPackages 期望沉底保留的应用包名列表
     * @param closePackages 期望直接销毁的应用包名列表
     * @return 包含 "kept"(保留列表), "closed"(关闭列表及原因), "note"(提示信息) 的 Bundle
     */
    Bundle finishDisplay(int displayId, in String[] keepPackages, in String[] closePackages) = 11;


    // ==========================================
    // 3. 任务与屏幕层级查询 (Task & Window Inspection)
    // ==========================================

    /**
     * 获取指定虚拟屏当前顶层任务 ID，没有任务返回 -1。
     */
    int topTaskId(int displayId) = 12;

    /**
     * 获取指定虚拟屏当前顶层 Activity 的完整类名。
     */
    String topActivity(int displayId) = 13;

    /**
     * 查询指定任务 ID 顶层页面所属的包名。
     */
    String packageOfTask(int taskId) = 14;

    /**
     * 查询指定任务 ID 当前所在的 displayId，任务不存在返回 -1。
     */
    int displayOfTask(int taskId) = 15;

    /**
     * 查询指定应用当前是否在某个虚拟屏上运行，返回对应 displayId，不在任何虚拟屏返回 -1。
     */
    int displayOfPackage(String packageName) = 16;

    /**
     * 查询指定多用户下的应用当前所在的虚拟屏。
     */
    int displayOfPackageInUser(String packageName, int userId) = 17;

    /**
     * 查询指定任务所属的用户 ID (如分身用户)。
     */
    int userOfTask(int taskId) = 18;

    /**
     * 在不同屏幕之间迁移任务栈 (moveRootTaskToDisplay)。
     */
    boolean moveTask(int taskId, int displayId) = 19;


    // ==========================================
    // 4. 主屏冲突避让机制 (Main Screen Conflict Guard)
    // ==========================================

    /**
     * 检查目标应用在指定用户下是否在主屏处于可见状态（防干扰保护）。
     */
    boolean visibleOnMainScreen(String packageName, int userId) = 20;

    /**
     * 开启主屏任务监听窗口：捕获未来 windowMs 毫秒内主屏顶层任务变动。
     * 用于发现后台启动跳到主屏的弹窗任务，并拉回虚拟屏。
     *
     * @return 当前主屏顶层 taskId
     */
    int watchMainScreen(int windowMs) = 21;

    /**
     * 获取 sinceUptimeMs 以来在主屏新出现的任务列表 (Bundle 封装)。
     */
    Bundle mainArrivals(long sinceUptimeMs) = 22;


    // ==========================================
    // 5. 输入事件精准注入 (Input Event Injection)
    // ==========================================

    /**
     * 在虚拟屏指定坐标注入单击事件 (Down + Up)。
     */
    boolean injectTap(int displayId, int x, int y) = 23;

    /**
     * 在虚拟屏注入完整单指触摸手势轨迹 (按时间轴逐点分发)。
     *
     * @param xs 坐标 X 数组
     * @param ys 坐标 Y 数组
     * @param times 相对时间戳毫秒数组 (首个必须为 0)
     */
    boolean injectStroke(int displayId, in int[] xs, in int[] ys, in long[] times) = 24;

    /**
     * 注入单个按键事件 (KeyEvent)，受系统按键白名单保护，防止篡改音量/电源。
     */
    boolean injectKey(int displayId, int keyCode) = 25;

    /**
     * 注入组合按键 (如 Ctrl+A 全选, Ctrl+V 粘贴)。
     * @return 0: 未发送, 1: 完整投递, 2: 投递不确定
     */
    int injectCtrlKey(int displayId, int keyCode) = 26;

    /**
     * 针对虚拟屏顶层目标任务定向注入 ASCII 纯文本。
     * 自动通过 KeyCharacterMap 转换为键码序列投递。
     */
    int injectAsciiText(int displayId, int taskId, String packageName, String text) = 27;


    // ==========================================
    // 6. 音频静音与 AppOps 隔离 (Audio & Media Isolation)
    // ==========================================

    /**
     * 对指定应用设置静音 (AppOps PLAY_AUDIO -> ignore / allow)。
     * 首次静音会持久化记录原模式，解除静音时恢复。
     */
    boolean setAudioMuted(String packageName, boolean muted) = 28;

    /**
     * 获取指定应用的 PLAY_AUDIO 模式 (如 "allow", "ignore", "default")。
     */
    String getAudioMode(String packageName) = 29;

    /**
     * 设置指定应用的 PLAY_AUDIO 模式。
     */
    boolean setAudioMode(String packageName, String mode) = 30;

    /**
     * 多用户环境下设置分身应用的静音状态。
     */
    boolean setAudioMutedInUser(String packageName, int userId, boolean muted) = 31;

    /**
     * 多用户环境下获取分身应用的音频模式。
     */
    String getAudioModeInUser(String packageName, int userId) = 32;

    /**
     * 多用户环境下设置分身应用的音频模式。
     */
    boolean setAudioModeInUser(String packageName, int userId, String mode) = 33;


    // ==========================================
    // 7. 剪贴板安全与隔离 (Clipboard Isolation)
    // ==========================================

    /**
     * 以 Shell 身份设置剪贴板纯文本。
     * 自动附带 SUPPRESS_CLIPBOARD_OVERLAY（不弹主屏已复制浮层）并标为敏感数据。
     * @return 0: 已设置, 1: 读不到原剪贴板(未改动), 2: 设置失败
     */
    int setClipText(String text) = 34;

    /**
     * 恢复设置之前的原剪贴板内容。
     */
    boolean restoreClip() = 35;

    /**
     * 获取已备份的用户原剪贴板文本。
     */
    String savedClipText() = 36;

    /**
     * 条件还原剪贴板：当剪贴板仍是 ours 时还原为 original，若用户已改动则不覆盖。
     */
    boolean restoreClipText(String original, String ours) = 37;


    // ==========================================
    // 8. 多用户与系统信息支持 (Multi-User & Profile Support)
    // ==========================================

    /**
     * 列出系统所有用户 (pm list users 原样输出)。
     */
    String listUsers() = 38;

    /**
     * 列出指定用户下的所有已安装包 (pm list packages --user <userId>)。
     */
    String listPackages(int userId) = 39;

    /**
     * 检查目标包是否为系统预装应用。
     */
    boolean isSystemPackage(String packageName) = 40;

    /**
     * 获取系统中可用于应用双开的分身用户列表及摘要 (Bundle: users, summary)。
     */
    Bundle appCopyUsers() = 41;


    // ==========================================
    // 9. 设备唤醒与主屏准备 (Device Unlock & Keyguard)
    // ==========================================

    /**
     * 点亮屏幕 (Wakeup)。
     */
    boolean wakeDevice() = 42;

    /**
     * 解除无密码/滑动锁屏。
     */
    boolean dismissDeviceKeyguard() = 43;

    /**
     * 在通知/指纹锁屏页向上滑动调出凭据输入页。
     */
    boolean revealDeviceCredential() = 44;

    /**
     * 在锁屏界面点击回退按钮（如“使用密码”）。
     */
    boolean revealDeviceCredentialTap(int x, int y) = 45;

    /**
     * 安全注入锁屏凭据 (PIN/Password)。凭据直接走 Binder，不进入 shell 命令行日志。
     */
    boolean enterDeviceCredential(int kind, in byte[] credential, int clear) = 46;


    // ==========================================
    // 10. 系统命令与进程标识 (System Execution & Identity)
    // ==========================================

    /**
     * 返回服务端守护进程的 [uid, pid]。
     */
    int[] identity() = 47;

    /**
     * 以 Shell 身份执行系统命令，返回包含 exitCode (int) 和 output (String) 的 Bundle。
     */
    Bundle runCommand(String command) = 48;

    /**
     * 在指定虚拟屏的环境上下文中执行命令（注入 AGENT_DISPLAY_ID 环境变量）。
     */
    Bundle runSystemCommand(int displayId, String command) = 49;

    // ==========================================
    // 11. 原生网络嗅探与抓包 (Native Network Capture)
    // ==========================================

    /**
     * 获取服务端原生网络捕获控制器 (eBPF Root 抓包引擎)。
     */
    INetworkCapture getNetworkCapture() = 50;
}
