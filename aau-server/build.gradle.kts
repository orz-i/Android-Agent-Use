import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import java.util.zip.ZipEntry

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

group = "com.agent.use"
version = "0.1.0"

android {
    namespace = "com.agent.use.server"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.agent.use.server"
        minSdk = 30
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        aidl = true
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    lint {
        // lifecycle 的 NonNullableMutableLiveDataDetector 与 Kotlin 2.1 分析 API 不兼容
        // （KaCallableMemberCall 期望接口），分析本模块源码时抛 IncompatibleClassChangeError。
        // 守护进程没有 LiveData，关掉这条检查。
        disable += "NullSafeMutableLiveData"
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":aau-common"))
    // 裸进程里的端上实体识别：类进 dex，libLiteRt.so 由 packageServerDex 一并导出。
    implementation(project(":aau-ner"))
    testImplementation(libs.junit)
    testImplementation(libs.kotlin.test)
}

// 独立构建 classes.dex 与 aau-server.jar (内含 classes.dex)
val packageServerDexTask = tasks.register("packageServerDex") {
    group = "build"
    description = "Assembles standalone classes.dex and aau-server.jar for app_process/Shizuku"
    dependsOn("assembleRelease")

    doLast {
        val buildDir = layout.buildDirectory.asFile.get()
        val apkFile = File(buildDir, "outputs/apk/release/aau-server-release-unsigned.apk")
            .takeIf { it.exists() }
            ?: File(buildDir, "outputs/apk/release/aau-server-release.apk")
            .takeIf { it.exists() }
            ?: File(buildDir, "outputs/apk/release/agent-display-server-release-unsigned.apk")
            .takeIf { it.exists() }
            ?: File(buildDir, "outputs/apk/release/agent-display-server-release.apk")

        if (apkFile != null && apkFile.exists()) {
            val outputsDir = File(buildDir, "outputs")
            outputsDir.mkdirs()
            val outputJar = File(outputsDir, "aau-server.jar")
            val outputDex = File(outputsDir, "classes.dex")

            // 从 APK 中提取 classes.dex 并打包为 aau-server.jar 与 classes.dex
            ZipFile(apkFile).use { zip ->
                val dexEntry = zip.getEntry("classes.dex")
                if (dexEntry != null) {
                    // 提取 classes.dex
                    zip.getInputStream(dexEntry).use { input ->
                        outputDex.outputStream().use { output ->
                            input.copyTo(output)
                        }
                    }

                    // 打包 aau-server.jar
                    ZipOutputStream(outputJar.outputStream()).use { outZip ->
                        outZip.putNextEntry(ZipEntry("classes.dex"))
                        outputDex.inputStream().copyTo(outZip)
                        outZip.closeEntry()
                    }
                    println("Successfully extracted classes.dex: ${outputDex.absolutePath} (${outputDex.length()} bytes)")
                    println("Successfully created standalone server jar: ${outputJar.absolutePath} (${outputJar.length()} bytes)")
                } else {
                    println("Warning: classes.dex not found in ${apkFile.name}")
                }

                // app_process 没有 nativeLibraryDir，LiteRT 要按绝对路径 System.load（见 NativeLibraries）。
                // 单独导出，部署时放到 /data/local/tmp/aau/lib/ 或 jar 同级的 lib/。
                val soEntry = zip.getEntry("lib/arm64-v8a/libLiteRt.so")
                if (soEntry != null) {
                    val soFile = File(buildDir, "outputs/native/arm64-v8a/libLiteRt.so")
                    soFile.parentFile.mkdirs()
                    zip.getInputStream(soEntry).use { input ->
                        soFile.outputStream().use { output -> input.copyTo(output) }
                    }
                    println("Extracted libLiteRt.so: ${soFile.absolutePath} (${soFile.length()} bytes)")
                } else {
                    println("Warning: lib/arm64-v8a/libLiteRt.so not found in ${apkFile.name}")
                }
            }
        }
    }
}

tasks.register("packageServerJar") {
    group = "build"
    description = "Alias for packageServerDex"
    dependsOn(packageServerDexTask)
}
