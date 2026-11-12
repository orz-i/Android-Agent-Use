import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import java.util.zip.ZipEntry

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

group = "com.agent.display"
version = "0.1.0"

android {
    namespace = "com.agent.display.server"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.agent.display.server"
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
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":agent-display-common"))
}

// 独立构建 classes.dex 与 agent-display-server.jar (内含 classes.dex)
val packageServerDexTask = tasks.register("packageServerDex") {
    group = "build"
    description = "Assembles standalone classes.dex and agent-display-server.jar for app_process/Shizuku"
    dependsOn("assembleRelease")

    doLast {
        val buildDir = layout.buildDirectory.asFile.get()
        val apkFile = File(buildDir, "outputs/apk/release/agent-display-server-release-unsigned.apk")
            .takeIf { it.exists() }
            ?: File(buildDir, "outputs/apk/release/agent-display-server-release.apk")

        if (apkFile != null && apkFile.exists()) {
            val outputsDir = File(buildDir, "outputs")
            outputsDir.mkdirs()
            val outputJar = File(outputsDir, "agent-display-server.jar")
            val outputDex = File(outputsDir, "classes.dex")

            // 从 APK 中提取 classes.dex 并打包为 agent-display-server.jar 与 classes.dex
            ZipFile(apkFile).use { zip ->
                val dexEntry = zip.getEntry("classes.dex")
                if (dexEntry != null) {
                    // 提取 classes.dex
                    zip.getInputStream(dexEntry).use { input ->
                        outputDex.outputStream().use { output ->
                            input.copyTo(output)
                        }
                    }

                    // 打包 agent-display-server.jar
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
            }
        }
    }
}

tasks.register("packageServerJar") {
    group = "build"
    description = "Alias for packageServerDex"
    dependsOn(packageServerDexTask)
}
