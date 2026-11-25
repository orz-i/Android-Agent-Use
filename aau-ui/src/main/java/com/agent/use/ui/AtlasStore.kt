package com.agent.use.ui

/**
 * 按包名分存的 App 页面地图存储接口；落盘、并发锁与本地加密由 app 层实现。
 */
interface AtlasStore {
    /** 已记录的所有包名。 */
    fun listPackages(): List<String>

    /** 读取指定包名的页面地图；不存在返回 null。 */
    fun get(packageName: String): AppAtlas?

    /** 列出所有已存页面地图。默认逐包读取，实现类可覆盖以在锁内批量读取。 */
    fun all(): List<AppAtlas> = listPackages().mapNotNull(::get)

    /** 写入或覆盖指定包名的页面地图。 */
    fun put(atlas: AppAtlas)

    /** 删除指定包名的页面地图。 */
    fun remove(packageName: String)

    /** 清空全部包的页面地图。 */
    fun clear()

    /**
     * 原子读改写指定包名的页面地图；[change] 返回 null 表示不修改。
     * 并发实现应在锁内完成读取、变换与写回。
     */
    fun update(packageName: String, change: (AppAtlas?) -> AppAtlas?): AppAtlas? {
        val next = change(get(packageName)) ?: return null
        put(next)
        return next
    }
}

/** 内存实现（线程安全），供纯 JVM 单元测试与无盘场景使用。 */
class InMemoryAtlasStore : AtlasStore {
    private val map = LinkedHashMap<String, AppAtlas>()

    @Synchronized
    override fun listPackages(): List<String> = map.keys.toList()

    @Synchronized
    override fun get(packageName: String): AppAtlas? = map[packageName]

    @Synchronized
    override fun all(): List<AppAtlas> = map.values.toList()

    @Synchronized
    override fun put(atlas: AppAtlas) {
        map[atlas.packageName] = atlas
    }

    @Synchronized
    override fun remove(packageName: String) {
        map.remove(packageName)
    }

    @Synchronized
    override fun clear() {
        map.clear()
    }

    @Synchronized
    override fun update(packageName: String, change: (AppAtlas?) -> AppAtlas?): AppAtlas? {
        val next = change(map[packageName]) ?: return null
        map[packageName] = next
        return next
    }
}
