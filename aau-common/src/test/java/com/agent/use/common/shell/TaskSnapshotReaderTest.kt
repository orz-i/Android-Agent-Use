package com.agent.use.common.shell

import android.content.ComponentName
import android.content.ContextWrapper
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.content.pm.FeatureInfo
import android.content.pm.InstrumentationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.content.pm.PermissionGroupInfo
import android.content.pm.PermissionInfo
import android.content.pm.ProviderInfo
import android.content.pm.ResolveInfo
import android.content.pm.SharedLibraryInfo
import android.content.pm.VersionedPackage
import android.graphics.Rect
import android.graphics.drawable.Drawable
import android.os.UserHandle
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

class TaskSnapshotReaderTest {

    @Test
    fun resolveUidUsesGetPackageUidAsUser3AndCachesPositiveHits() {
        val queries = AtomicInteger(0)
        val pm = object : FakePackageManager() {
            @Suppress("unused")
            fun getPackageUidAsUser(packageName: String, flags: Int, userId: Int): Int {
                queries.incrementAndGet()
                val appId = when (packageName) {
                    "com.tencent.mm" -> 10123
                    "com.tencent.payment" -> 10456
                    else -> -1
                }
                return if (appId >= 0) userId * 100_000 + appId else -1
            }
        }
        val reader = TaskSnapshotReader(
            context = object : ContextWrapper(null) {
                override fun getPackageManager(): PackageManager = pm
            },
            defaultUserId = 0,
        )

        // 用户 0 与分身用户 999 必须映射到各自完整 UID
        assertEquals(10123, reader.resolveUid("com.tencent.mm", userId = 0))
        assertEquals(999 * 100_000 + 10123, reader.resolveUid("com.tencent.mm", userId = 999))
        assertEquals(10456, reader.resolveUid("com.tencent.payment", userId = 0))
        assertEquals(3, queries.get())

        // 命中缓存不再触发 PackageManager 查询
        assertEquals(10123, reader.resolveUid("com.tencent.mm", userId = 0))
        assertEquals(999 * 100_000 + 10123, reader.resolveUid("com.tencent.mm", userId = 999))
        assertEquals(3, queries.get())

        // 未找到的包返回 UNKNOWN (-1) 且不污染缓存
        assertEquals(-1, reader.resolveUid("com.missing.app", userId = 0))
        assertEquals(4, queries.get())

        // 匹配 preferredTopUid 时直接复用零 IPC；userId 不匹配时回退重新查询
        assertEquals(
            10123,
            reader.resolveUid("com.tencent.mm", userId = 0, preferredTopPkg = "com.tencent.mm", preferredTopUid = 10123),
        )
        assertEquals(4, queries.get())
    }

    @Test
    fun resolveUidFallsBackToTwoArgUidAndAppInfoAsUserAndUserHandleArithmetic() {
        val twoArgQueries = AtomicInteger(0)
        val pmTwoArg = object : FakePackageManager() {
            @Suppress("unused")
            fun getPackageUidAsUser(packageName: String, userId: Int): Int {
                twoArgQueries.incrementAndGet()
                return if (packageName == "com.app.a") userId * 100_000 + 10222 else -1
            }
        }
        val readerTwoArg = TaskSnapshotReader(
            context = object : ContextWrapper(null) {
                override fun getPackageManager(): PackageManager = pmTwoArg
            },
        )
        assertEquals(10 * 100_000 + 10222, readerTwoArg.resolveUid("com.app.a", userId = 10))
        assertEquals(1, twoArgQueries.get())

        val pmAppInfoAsUser = object : FakePackageManager() {
            @Suppress("unused")
            fun getApplicationInfoAsUser(packageName: String, flags: Int, userId: Int): ApplicationInfo {
                if (packageName != "com.app.b") throw NameNotFoundException(packageName)
                return ApplicationInfo().apply { uid = userId * 100_000 + 10333 }
            }
        }
        val readerAppInfoAsUser = TaskSnapshotReader(
            context = object : ContextWrapper(null) {
                override fun getPackageManager(): PackageManager = pmAppInfoAsUser
            },
        )
        assertEquals(999 * 100_000 + 10333, readerAppInfoAsUser.resolveUid("com.app.b", userId = 999))

        val pmFallback = object : FakePackageManager() {
            override fun getApplicationInfo(packageName: String, flags: Int): ApplicationInfo {
                return ApplicationInfo().apply {
                    uid = when (packageName) {
                        "com.tencent.mm" -> 10123
                        else -> throw NameNotFoundException(packageName)
                    }
                }
            }
        }
        val readerFallback = TaskSnapshotReader(
            context = object : ContextWrapper(null) {
                override fun getPackageManager(): PackageManager = pmFallback
            },
        )
        assertEquals(10123, readerFallback.resolveUid("com.tencent.mm", userId = 0))
        assertEquals(999 * 100_000 + 10123, readerFallback.resolveUid("com.tencent.mm", userId = 999))
        assertEquals(-1, readerFallback.resolveUid("com.nonexistent.pkg", userId = 0))
    }

    private open class FakePackageManager : PackageManager() {
        override fun getPackageInfo(packageName: String, flags: Int): PackageInfo = throw UnsupportedOperationException()
        override fun getPackageInfo(versionedPackage: VersionedPackage, flags: Int): PackageInfo = throw UnsupportedOperationException()
        override fun currentToCanonicalPackageNames(packageNames: Array<out String>): Array<String> = emptyArray()
        override fun canonicalToCurrentPackageNames(packageNames: Array<out String>): Array<String> = emptyArray()
        override fun getLaunchIntentForPackage(packageName: String): Intent? = null
        override fun getLeanbackLaunchIntentForPackage(packageName: String): Intent? = null
        override fun getPackageGids(packageName: String): IntArray? = null
        override fun getPackageGids(packageName: String, flags: Int): IntArray? = null
        override fun getPackageUid(packageName: String, flags: Int): Int = -1
        override fun getPermissionInfo(permName: String, flags: Int): PermissionInfo = throw UnsupportedOperationException()
        override fun queryPermissionsByGroup(permissionGroup: String?, flags: Int): List<PermissionInfo> = emptyList()
        override fun getPermissionGroupInfo(groupName: String, flags: Int): PermissionGroupInfo = throw UnsupportedOperationException()
        override fun getAllPermissionGroups(flags: Int): List<PermissionGroupInfo> = emptyList()
        override fun getApplicationInfo(packageName: String, flags: Int): ApplicationInfo = throw NameNotFoundException(packageName)
        override fun getActivityInfo(component: ComponentName, flags: Int): ActivityInfo = throw UnsupportedOperationException()
        override fun getReceiverInfo(component: ComponentName, flags: Int): ActivityInfo = throw UnsupportedOperationException()
        override fun getServiceInfo(component: ComponentName, flags: Int): android.content.pm.ServiceInfo = throw UnsupportedOperationException()
        override fun getProviderInfo(component: ComponentName, flags: Int): ProviderInfo = throw UnsupportedOperationException()
        override fun getInstalledPackages(flags: Int): List<PackageInfo> = emptyList()
        override fun getPackagesHoldingPermissions(permissions: Array<out String>, flags: Int): List<PackageInfo> = emptyList()
        override fun checkPermission(permName: String, packageName: String): Int = PERMISSION_DENIED
        override fun isPermissionRevokedByPolicy(permName: String, packageName: String): Boolean = false
        override fun addPermission(info: PermissionInfo): Boolean = false
        override fun addPermissionAsync(info: PermissionInfo): Boolean = false
        override fun removePermission(permName: String) {}
        override fun checkSignatures(packageName1: String, packageName2: String): Int = SIGNATURE_NO_MATCH
        override fun checkSignatures(uid1: Int, uid2: Int): Int = SIGNATURE_NO_MATCH
        override fun getPackagesForUid(uid: Int): Array<String>? = null
        override fun getNameForUid(uid: Int): String? = null
        override fun getInstalledApplications(flags: Int): List<ApplicationInfo> = emptyList()
        override fun isInstantApp(): Boolean = false
        override fun isInstantApp(packageName: String): Boolean = false
        override fun getInstantAppCookieMaxBytes(): Int = 0
        override fun getInstantAppCookie(): ByteArray = ByteArray(0)
        override fun clearInstantAppCookie() {}
        override fun updateInstantAppCookie(cookie: ByteArray?) {}
        override fun getSystemSharedLibraryNames(): Array<String>? = null
        override fun getSharedLibraries(flags: Int): List<SharedLibraryInfo> = emptyList()
        override fun getChangedPackages(sequenceNumber: Int) = null
        override fun getSystemAvailableFeatures(): Array<FeatureInfo> = emptyArray()
        override fun hasSystemFeature(featureName: String): Boolean = false
        override fun hasSystemFeature(featureName: String, version: Int): Boolean = false
        override fun resolveActivity(intent: Intent, flags: Int): ResolveInfo? = null
        override fun queryIntentActivities(intent: Intent, flags: Int): List<ResolveInfo> = emptyList()
        override fun queryIntentActivityOptions(caller: ComponentName?, specifics: Array<out Intent>?, intent: Intent, flags: Int): List<ResolveInfo> = emptyList()
        override fun queryBroadcastReceivers(intent: Intent, flags: Int): List<ResolveInfo> = emptyList()
        override fun resolveService(intent: Intent, flags: Int): ResolveInfo? = null
        override fun queryIntentServices(intent: Intent, flags: Int): List<ResolveInfo> = emptyList()
        override fun queryIntentContentProviders(intent: Intent, flags: Int): List<ResolveInfo> = emptyList()
        override fun resolveContentProvider(authority: String, flags: Int): ProviderInfo? = null
        override fun queryContentProviders(processName: String?, uid: Int, flags: Int): List<ProviderInfo> = emptyList()
        override fun getInstrumentationInfo(className: ComponentName, flags: Int): InstrumentationInfo = throw UnsupportedOperationException()
        override fun queryInstrumentation(targetPackage: String, flags: Int): List<InstrumentationInfo> = emptyList()
        override fun getDrawable(packageName: String, resid: Int, appInfo: ApplicationInfo?): Drawable? = null
        override fun getActivityIcon(activityName: ComponentName): Drawable = throw UnsupportedOperationException()
        override fun getActivityIcon(intent: Intent): Drawable = throw UnsupportedOperationException()
        override fun getActivityBanner(activityName: ComponentName): Drawable = throw UnsupportedOperationException()
        override fun getActivityBanner(intent: Intent): Drawable = throw UnsupportedOperationException()
        override fun getDefaultActivityIcon(): Drawable = throw UnsupportedOperationException()
        override fun getApplicationIcon(info: ApplicationInfo): Drawable = throw UnsupportedOperationException()
        override fun getApplicationIcon(packageName: String): Drawable = throw UnsupportedOperationException()
        override fun getApplicationBanner(info: ApplicationInfo): Drawable = throw UnsupportedOperationException()
        override fun getApplicationBanner(packageName: String): Drawable = throw UnsupportedOperationException()
        override fun getActivityLogo(activityName: ComponentName): Drawable = throw UnsupportedOperationException()
        override fun getActivityLogo(intent: Intent): Drawable = throw UnsupportedOperationException()
        override fun getApplicationLogo(info: ApplicationInfo): Drawable = throw UnsupportedOperationException()
        override fun getApplicationLogo(packageName: String): Drawable = throw UnsupportedOperationException()
        override fun getUserBadgedIcon(drawable: Drawable, user: UserHandle): Drawable = drawable
        override fun getUserBadgedDrawableForDensity(drawable: Drawable, user: UserHandle, badgeLocation: Rect?, badgeDensity: Int): Drawable = drawable
        override fun getUserBadgedLabel(label: CharSequence, user: UserHandle): CharSequence = label
        override fun getText(packageName: String, resid: Int, appInfo: ApplicationInfo?): CharSequence? = null
        override fun getXml(packageName: String, resid: Int, appInfo: ApplicationInfo?): android.content.res.XmlResourceParser? = null
        override fun getApplicationLabel(info: ApplicationInfo): CharSequence = ""
        override fun getResourcesForActivity(activityName: ComponentName): android.content.res.Resources = throw UnsupportedOperationException()
        override fun getResourcesForApplication(app: ApplicationInfo): android.content.res.Resources = throw UnsupportedOperationException()
        override fun getResourcesForApplication(appPackageName: String): android.content.res.Resources = throw UnsupportedOperationException()
        override fun verifyPendingInstall(id: Int, verificationCode: Int) {}
        override fun extendVerificationTimeout(id: Int, verificationCodeAtTimeout: Int, millisecondsAfterTimeout: Long) {}
        override fun setInstallerPackageName(targetPackage: String, installerPackageName: String?) {}
        override fun getInstallerPackageName(packageName: String): String? = null
        override fun addPackageToPreferred(packageName: String) {}
        override fun removePackageFromPreferred(packageName: String) {}
        override fun getPreferredPackages(flags: Int): List<PackageInfo> = emptyList()
        override fun addPreferredActivity(filter: IntentFilter, match: Int, set: Array<out ComponentName>?, activity: ComponentName) {}
        override fun clearPackagePreferredActivities(packageName: String) {}
        override fun getPreferredActivities(outFilters: MutableList<IntentFilter>, outActivities: MutableList<ComponentName>, packageName: String?): Int = 0
        override fun setComponentEnabledSetting(componentName: ComponentName, newState: Int, flags: Int) {}
        override fun getComponentEnabledSetting(componentName: ComponentName): Int = COMPONENT_ENABLED_STATE_DEFAULT
        override fun setApplicationEnabledSetting(packageName: String, newState: Int, flags: Int) {}
        override fun getApplicationEnabledSetting(packageName: String): Int = COMPONENT_ENABLED_STATE_DEFAULT
        override fun isSafeMode(): Boolean = false
        override fun setApplicationCategoryHint(packageName: String, categoryHint: Int) {}
        override fun getPackageInstaller(): PackageInstaller = throw UnsupportedOperationException()
        override fun canRequestPackageInstalls(): Boolean = false
    }
}
