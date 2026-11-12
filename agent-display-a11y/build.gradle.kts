plugins {
    id("com.android.library")
    alias(libs.plugins.kotlin.android)
    `maven-publish`
}

group = "com.agent.display"
version = "0.1.0"

android {
    namespace = "com.agent.display.a11y"
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

    testOptions {
        unitTests.isReturnDefaultValues = true
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
    implementation(project(":agent-display-common"))
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.kotlin.test)
}

afterEvaluate {
    publishing {
        publications {
            register<MavenPublication>("release") {
                from(components["release"])
                groupId = "com.agent.display"
                artifactId = "agent-display-a11y"
                version = "0.1.0"

                pom {
                    name.set("agent-display-a11y")
                    description.set("Android Agent Use - Accessibility Extensions for Virtual Display UI Tree and Gestures")
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
