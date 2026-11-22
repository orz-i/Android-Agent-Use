plugins { id("com.android.library") }

android {
    namespace = "com.agent.use.litert"
    compileSdk = 36
    defaultConfig { minSdk = 30 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

// Java-only on purpose, and `implementation` rather than `api`: the artifact carries Kotlin 2.4
// metadata, which would otherwise reach a Kotlin 2.1 consumer's compile classpath. Callers see
// only these two classes and never the LiteRT types.
dependencies { implementation("com.google.ai.edge.litert:litert:2.3.2") }
