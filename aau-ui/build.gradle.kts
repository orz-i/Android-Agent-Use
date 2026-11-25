plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    `java-library`
    `maven-publish`
}

group = "com.agent.use"
version = "0.1.0"

// 纯 JVM：读屏快照模型、稳定编号、等待与诊断全是数据与状态机，不含任何 Android 类型。
// 宿主（Android 或桌面测试）实现 ScreenSurface 即可复用这一层。
java {
    toolchain { languageVersion = JavaLanguageVersion.of(17) }
    withSourcesJar()
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    api(libs.kotlinx.coroutines.core)
    api(libs.kotlinx.serialization.json)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.kotlin.test)
}

afterEvaluate {
    publishing {
        publications {
            register<MavenPublication>("release") {
                from(components["java"])
                groupId = "com.agent.use"
                artifactId = "aau-ui"
                version = "0.1.0"

                pom {
                    name.set("aau-ui")
                    description.set("Android Agent Use - screen snapshot model, stable refs, waiting and diagnosis")
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
