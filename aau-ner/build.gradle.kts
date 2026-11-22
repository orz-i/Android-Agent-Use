plugins {
    id("com.android.library")
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.agent.use.ner"
    compileSdk = 36

    defaultConfig {
        minSdk = 30
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        // lifecycle 的 NonNullableMutableLiveDataDetector 与本仓库的 Kotlin 2.1 分析 API 不兼容：
        // 分析 AauEntityExtractor.kt 时抛 IncompatibleClassChangeError（KaCallableMemberCall 期望接口），
        // 直接把 release 构建带崩。这个模块没有 LiveData，关掉这条检查。
        disable += "NullSafeMutableLiveData"
    }
}

kotlin { jvmToolchain(17) }

dependencies {
    implementation(project(":aau-litert"))
    testImplementation(libs.junit)
    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
