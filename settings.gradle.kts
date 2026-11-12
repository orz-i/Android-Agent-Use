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
