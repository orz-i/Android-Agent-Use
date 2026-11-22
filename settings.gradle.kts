pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "Android-Agent-Use"

include(":aau-common")
include(":aau-server")
include(":aau-client")
include(":aau-a11y")
include(":aau-setup")
include(":aau-remote")

// Always in the build, independent of `aauVisionBackend`: `:aau-litert` is the Java boundary
// over the LiteRT artifact, `:aau-ner` the text extractor on top of it. The icon detector keeps
// the opt-in backend switch; the text side has no second backend to switch to.
include(":aau-litert")
include(":aau-ner")

val aauVisionBackend = providers.gradleProperty("aauVisionBackend").orElse("off").get()
require(aauVisionBackend in setOf("off", "litert", "mnn")) { "aauVisionBackend must be off, litert or mnn" }
if (aauVisionBackend != "off") include(":aau-vision")
