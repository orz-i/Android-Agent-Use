package com.agent.use.common.shell

import android.annotation.SuppressLint
import android.content.ComponentName
import android.content.Context
import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.agent.use.common.LaunchOrigin
import java.lang.reflect.Field
import java.lang.reflect.Method
import java.util.concurrent.ConcurrentHashMap

/**
 * 将系统 `TaskInfo` 列表读取为 [CustodyTracker.TaskRow]，提取多包名并解析按用户区分的完整 UID。
 */
@SuppressLint("PrivateApi")
class TaskSnapshotReader(
    private val context: Context,
    private val defaultUserId: Int = 0,
) {
    private data class PkgUser(val packageName: String, val userId: Int)

    private val uidCache = ConcurrentHashMap<PkgUser, Int>()

    private val pmClass: Class<out PackageManager> by lazy { context.packageManager.javaClass }
    private val getPackageUidAsUser3: Method? by lazy {
        runCatching {
            pmClass.getMethod("getPackageUidAsUser", String::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
        }.getOrNull()
    }
    private val getPackageUidAsUser2: Method? by lazy {
        runCatching {
            pmClass.getMethod("getPackageUidAsUser", String::class.java, Int::class.javaPrimitiveType)
        }.getOrNull()
    }
    private val getApplicationInfoAsUser3: Method? by lazy {
        runCatching {
            pmClass.getMethod("getApplicationInfoAsUser", String::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
        }.getOrNull()
    }

    fun read(rawTasks: List<Any>): List<CustodyTracker.TaskRow> {
        val idField = TASK_ID_FIELD ?: return emptyList()
        val displayField = DISPLAY_ID_FIELD ?: return emptyList()
        val rows = ArrayList<CustodyTracker.TaskRow>(rawTasks.size)
        for (task in rawTasks) {
            val row = readOne(task, idField, displayField) ?: continue
            rows += row
        }
        return rows
    }

    private fun readOne(task: Any, idField: Field, displayField: Field): CustodyTracker.TaskRow? {
        val taskId = runCatching { idField.getInt(task) }.getOrNull() ?: return null
        val displayId = runCatching { displayField.getInt(task) }.getOrNull() ?: return null
        val userId = runCatching { USER_ID_FIELD?.getInt(task) }.getOrNull() ?: defaultUserId

        val top = runCatching { TOP_ACTIVITY_FIELD?.get(task) as? ComponentName }.getOrNull()
        val base = runCatching { BASE_ACTIVITY_FIELD?.get(task) as? ComponentName }.getOrNull()
        val real = runCatching { REAL_ACTIVITY_FIELD?.get(task) as? ComponentName }.getOrNull()
        val orig = runCatching { ORIG_ACTIVITY_FIELD?.get(task) as? ComponentName }.getOrNull()
        val topInfo = runCatching { TOP_ACTIVITY_INFO_FIELD?.get(task) as? ActivityInfo }.getOrNull()
        val topInfoUid = topInfo?.applicationInfo?.uid?.takeIf { it >= 0 }
        val topInfoPkg = topInfo?.packageName?.takeIf { it.isNotBlank() }

        if (topInfoUid != null && topInfoPkg != null) {
            cacheUid(topInfoPkg, topInfoUid / PER_USER_RANGE, topInfoUid)
        }

        val packages = LinkedHashSet<String>(4)
        top?.packageName?.takeIf { it.isNotBlank() }?.let(packages::add)
        base?.packageName?.takeIf { it.isNotBlank() }?.let(packages::add)
        real?.packageName?.takeIf { it.isNotBlank() }?.let(packages::add)
        orig?.packageName?.takeIf { it.isNotBlank() }?.let(packages::add)
        topInfoPkg?.let(packages::add)

        val uids = LinkedHashSet<Int>(packages.size + 1)
        if (topInfoUid != null) {
            uids.add(topInfoUid)
        }
        for (pkg in packages) {
            val uid = resolveUid(pkg, userId, top?.packageName ?: topInfoPkg, topInfoUid)
            if (uid >= 0) uids.add(uid)
        }

        val primaryPkg = top?.packageName ?: base?.packageName ?: real?.packageName ?: orig?.packageName ?: topInfoPkg
        val primaryUid = if (primaryPkg != null) {
            resolveUid(primaryPkg, userId, top?.packageName ?: topInfoPkg, topInfoUid)
        } else {
            topInfoUid ?: LaunchOrigin.UNKNOWN_UID
        }

        val type = runCatching { TOP_ACTIVITY_TYPE_FIELD?.getInt(task) }.getOrNull()
        val standard = type == null || type == ACTIVITY_TYPE_UNDEFINED || type == ACTIVITY_TYPE_STANDARD

        return CustodyTracker.TaskRow(
            taskId = taskId,
            displayId = displayId,
            packageName = primaryPkg,
            userId = userId,
            topActivity = top?.className,
            standard = standard,
            uids = uids,
            primaryUid = primaryUid,
        )
    }

    fun resolveUid(
        packageName: String,
        userId: Int,
        preferredTopPkg: String? = null,
        preferredTopUid: Int? = null,
    ): Int {
        if (packageName.isBlank()) return LaunchOrigin.UNKNOWN_UID
        if (preferredTopUid != null && preferredTopUid >= 0 && packageName == preferredTopPkg) {
            if (userId < 0 || preferredTopUid / PER_USER_RANGE == userId) {
                return preferredTopUid
            }
        }
        val key = PkgUser(packageName, userId)
        uidCache[key]?.let { return it }

        val resolved = queryUid(packageName, userId)
        if (resolved >= 0) {
            cacheUid(packageName, userId, resolved)
        }
        return resolved
    }

    private fun queryUid(packageName: String, userId: Int): Int {
        val pm = context.packageManager
        if (userId >= 0) {
            runCatching { getPackageUidAsUser3?.invoke(pm, packageName, 0, userId) as? Int }
                .getOrNull()?.takeIf { it >= 0 }?.let { return it }
            runCatching { getPackageUidAsUser2?.invoke(pm, packageName, userId) as? Int }
                .getOrNull()?.takeIf { it >= 0 }?.let { return it }
            runCatching { (getApplicationInfoAsUser3?.invoke(pm, packageName, 0, userId) as? ApplicationInfo)?.uid }
                .getOrNull()?.takeIf { it >= 0 }?.let { return it }
        }
        val baseUid = runCatching { pm.getApplicationInfo(packageName, 0).uid }.getOrNull()?.takeIf { it >= 0 }
            ?: return LaunchOrigin.UNKNOWN_UID
        return if (userId >= 0) userId * PER_USER_RANGE + (baseUid % PER_USER_RANGE) else baseUid
    }

    private fun cacheUid(packageName: String, userId: Int, uid: Int) {
        if (uidCache.size >= MAX_CACHE_ENTRIES) {
            uidCache.clear()
        }
        uidCache[PkgUser(packageName, userId)] = uid
    }

    companion object {
        private const val PER_USER_RANGE = 100_000
        private const val ACTIVITY_TYPE_UNDEFINED = 0
        private const val ACTIVITY_TYPE_STANDARD = 1
        private const val MAX_CACHE_ENTRIES = 512

        private val TASK_INFO: Class<*>? by lazy { runCatching { Class.forName("android.app.TaskInfo") }.getOrNull() }
        private val TASK_ID_FIELD: Field? by lazy { runCatching { TASK_INFO?.getField("taskId") }.getOrNull() }
        private val DISPLAY_ID_FIELD: Field? by lazy { runCatching { TASK_INFO?.getField("displayId") }.getOrNull() }
        private val USER_ID_FIELD: Field? by lazy { runCatching { TASK_INFO?.getField("userId") }.getOrNull() }
        private val TOP_ACTIVITY_FIELD: Field? by lazy { runCatching { TASK_INFO?.getField("topActivity") }.getOrNull() }
        private val BASE_ACTIVITY_FIELD: Field? by lazy { runCatching { TASK_INFO?.getField("baseActivity") }.getOrNull() }
        private val REAL_ACTIVITY_FIELD: Field? by lazy { runCatching { TASK_INFO?.getField("realActivity") }.getOrNull() }
        private val ORIG_ACTIVITY_FIELD: Field? by lazy { runCatching { TASK_INFO?.getField("origActivity") }.getOrNull() }
        private val TOP_ACTIVITY_INFO_FIELD: Field? by lazy { runCatching { TASK_INFO?.getField("topActivityInfo") }.getOrNull() }
        private val TOP_ACTIVITY_TYPE_FIELD: Field? by lazy { runCatching { TASK_INFO?.getField("topActivityType") }.getOrNull() }
    }
}
