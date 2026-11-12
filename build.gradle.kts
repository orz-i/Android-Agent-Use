plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.jvm) apply false
}

// 顶级快捷任务：packageServerDex
tasks.register("packageServerDex") {
    group = "build"
    description = "Assembles standalone aau-server.jar and classes.dex"
    dependsOn(":aau-server:packageServerDex")
}
