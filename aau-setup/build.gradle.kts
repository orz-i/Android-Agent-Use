plugins {
    id("com.android.library")
    alias(libs.plugins.kotlin.android)
    `maven-publish`
}

group = "com.agent.use"
version = "0.1.0"

android {
    namespace = "com.agent.use.setup"
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

    buildFeatures {
        aidl = false
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
    implementation(project(":aau-common"))
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
                groupId = "com.agent.use"
                artifactId = "aau-setup"
                version = "0.1.0"

                pom {
                    name.set("aau-setup")
                    description.set("Android Agent Use - Privilege Launchers, Preflight Compatibility & Diagnostic Suite")
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
