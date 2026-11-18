plugins {
    `java-library`
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    `maven-publish`
}

group = "com.agent.use"
version = "0.1.0"

kotlin {
    jvmToolchain(17)
}

java {
    withSourcesJar()
}

dependencies {
    // API 面直接暴露 JsonObject / StateFlow / OkHttp 客户端，消费者要能看见
    api(libs.kotlinx.coroutines.core)
    api(libs.kotlinx.serialization.json)
    api(libs.okhttp)

    testImplementation(libs.junit)
    testImplementation(libs.kotlin.test)
}

publishing {
    publications {
        register<MavenPublication>("release") {
            from(components["java"])
            groupId = "com.agent.use"
            artifactId = "aau-remote"
            version = "0.1.0"

            pom {
                name.set("aau-remote")
                description.set("Android Agent Use - Remote orchestration bridge (task API v1 + MCP over HTTP)")
                url.set("https://github.com/orz-i/Android-Agent-Use")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
            }
        }
    }
}
