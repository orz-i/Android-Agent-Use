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

include(":agent-display-common")
include(":agent-display-server")
include(":agent-display-client")
include(":agent-display-a11y")
include(":agent-display-setup")
