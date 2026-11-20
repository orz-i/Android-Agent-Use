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

val aauVisionBackend = providers.gradleProperty("aauVisionBackend").orElse("off").get()
require(aauVisionBackend in setOf("off", "litert", "mnn")) { "aauVisionBackend must be off, litert or mnn" }
if (aauVisionBackend != "off") include(":aau-vision")
if (aauVisionBackend == "litert") {
    include(":aau-vision-litert")
    project(":aau-vision-litert").projectDir = file("aau-vision/litert-bridge")
}
