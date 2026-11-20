plugins { id("com.android.library") }

android {
    namespace = "com.agent.use.vision.litert"
    compileSdk = 36
    defaultConfig { minSdk = 30 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

// Keep the SDK's Kotlin 2.4 metadata off the host Kotlin compile classpath.
dependencies { implementation("com.google.ai.edge.litert:litert:2.3.2") }
