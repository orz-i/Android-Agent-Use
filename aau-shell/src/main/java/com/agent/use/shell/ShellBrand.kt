package com.agent.use.shell

/**
 * 内置助手与宿主之间的品牌与命名。
 *
 * 这些都只影响「给人看的名字」和「协议里必须写死的类名」，不改变配对、交接与看门狗的流程：
 *
 * - [appName] 只出现在给用户看的提示与电脑上那条启动脚本的注释里；
 * - [helperClass] 是启动命令里 `app_process` 的入口类全名，必须指向宿主 APK 里真实存在的类；
 * - [accessibilityService] 是宿主无障碍服务的组件全名，写回 `enabled_accessibility_services` 时要用；
 * - [certCommonName] 是 ADB 配对密钥证书的 CN，配对成功后会显示在设备的「已授权的调试设备」里；
 * - [exitMark] 是 shell 命令输出末尾的退出码标记，只有本库自己解析。
 *
 * 默认值指向 AAU 自己的示例实现；宿主必须在进程启动时用 [ShellBranding.configure] 换成自己的，
 * 否则起不来自己的助手进程（[helperClass] 指向不存在的类）。
 */
data class ShellBrand(
    val appName: String = "Android Agent Use",
    val helperClass: String = "com.agent.use.shell.HelperMain",
    val accessibilityService: String = "com.agent.use.a11y.AgentAccessibilityService",
    val certCommonName: String = "Android Agent Use",
    val exitMark: String = "__aau_exit=",
)

/**
 * 进程级的品牌配置。
 *
 * 配对与交接是跨进程的（App 与 shell 身份下的助手），两边必须用同一套 [ShellBrand]；
 * 而这些值是常量级的，所以在进程启动时设置一次即可。这里的可变状态是有意的：
 * [HelperHandoff] 与 [PermissionCommands] 都是 object，改造它们为实例会波及所有调用方，
 * 收益只是省掉一次进程级配置。
 */
object ShellBranding {
    @Volatile
    var brand: ShellBrand = ShellBrand()
        private set

    /** 设置进程品牌；重复调用以最后一次为准（测试里用来切换夹具）。 */
    fun configure(brand: ShellBrand) {
        this.brand = brand
    }
}
