plugins {
    id("com.android.library")
    alias(libs.plugins.kotlin.android)
    `maven-publish`
}

group = "com.agent.display"
version = "0.1.0"

android {
    namespace = "com.agent.display.common"
    compileSdk = 36

    defaultConfig {
        minSdk = 30
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        aidl = true
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.android)
}

afterEvaluate {
    publishing {
        publications {
            register<MavenPublication>("release") {
                from(components["release"])
                groupId = "com.agent.display"
                artifactId = "agent-display-common"
                version = "0.1.0"

                pom {
                    name.set("agent-display-common")
                    description.set("Android Agent Use - Common Protocol, AIDL Interfaces and Data Models")
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
