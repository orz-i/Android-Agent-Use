plugins {
    id("com.android.library")
    alias(libs.plugins.kotlin.android)
}

val backend = providers.gradleProperty("aauVisionBackend").get()

android {
    namespace = "com.agent.use.vision"
    compileSdk = 36

    defaultConfig {
        minSdk = 30
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        if (backend == "mnn") {
            ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
            val sourceDir = providers.gradleProperty("aauMnnSourceDir").orNull
                ?: error("MNN requires -PaauMnnSourceDir=<path to extracted MNN 3.6.2 source>")
            val source = file(sourceDir)
            require(source.resolve("include/MNN/Interpreter.hpp").isFile) { "Invalid aauMnnSourceDir: $source" }
            externalNativeBuild {
                cmake {
                    arguments += listOf("-DAAU_MNN_SOURCE=${source.invariantSeparatorsPath}", "-DANDROID_STL=c++_static")
                    targets += "aau_mnn_vision"
                }
            }
            consumerProguardFiles("src/mnn/consumer-rules.pro")
        }
    }

    if (backend == "mnn") {
        ndkVersion = "28.2.13676358"
        externalNativeBuild {
            cmake {
                path = file("src/mnn/cpp/CMakeLists.txt")
                version = "3.22.1"
            }
        }
    }

    sourceSets.getByName("main") {
        java.srcDir("src/$backend/java")
        assets.srcDir("src/$backend/assets")
    }
    androidResources { noCompress += setOf("tflite", "mnn") }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin { jvmToolchain(17) }

dependencies {
    if (backend == "litert") implementation(project(":aau-vision-litert"))
    testImplementation(libs.junit)
    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
