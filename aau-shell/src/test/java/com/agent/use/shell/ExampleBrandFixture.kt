package com.agent.use.shell

/**
 * 一套示例宿主品牌，用来验证「宿主能覆盖默认值」：配置一换，生成的命令、脚本与清单写入就跟着换。
 *
 * 用例里的期望值都按这套品牌写死，所以它不是随便编的名字 —— 改这里要同时改用例里的断言。
 *
 * 用 companion object 的 init 配置：好几个用例把 `PermissionCommands.accessibilityService(...)` 放在字段初始化里，
 * 那发生在 @Before 之前。
 */
internal fun configureExampleBrand() {
    ShellBranding.configure(
        ShellBrand(
            appName = "Example",
            helperClass = "com.example.app.shell.HelperMain",
            accessibilityService = "com.example.app.a11y.ExampleAccessibilityService",
            certCommonName = "Example",
            exitMark = "__example_exit=",
        ),
    )
}
