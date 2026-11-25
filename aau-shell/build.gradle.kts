plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-library`
    `maven-publish`
}

group = "com.agent.use"
version = "0.1.0"

// 纯 JVM：配对、ADB 协议、助手交接与看门狗都是 Java/Android 无关的状态机与字节协议，
// 宿主（Android 或桌面测试）只提供 BuiltinShellPlatform 的实现。刻意不用 android library，
// 否则纯 JVM 的接入方（比如桌面端内核模块）无法依赖。
java {
    toolchain { languageVersion = JavaLanguageVersion.of(17) }
    withSourcesJar()
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    api(libs.kotlinx.coroutines.core)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.kotlin.test)
    // 测试里的 TLS 1.3 与导出密钥:用和 Android 平台同源的 TLS 实现,只进测试类路径
    testImplementation(libs.conscrypt.openjdk.uber)
}

afterEvaluate {
    publishing {
        publications {
            register<MavenPublication>("release") {
                from(components["java"])
                groupId = "com.agent.use"
                artifactId = "aau-shell"
                version = "0.1.0"

                pom {
                    name.set("aau-shell")
                    description.set("Android Agent Use - ADB pairing, built-in shell helper handoff and watchdog")
                    url.set("https://github.com/orz-i/Android-Agent-Use")
                    licenses {
                        license {
                            name.set("The Apache License, Version 2.0")
                            url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                        }
                    }
                    developers {
                        developer {
                            id.set("orz-i")
                            name.set("Android-Agent-Use Team")
                        }
                    }
                    scm {
                        connection.set("scm:git:git://github.com/orz-i/Android-Agent-Use.git")
                        developerConnection.set("scm:git:ssh://github.com/orz-i/Android-Agent-Use.git")
                        url.set("https://github.com/orz-i/Android-Agent-Use")
                    }
                }
            }
        }
    }
}
