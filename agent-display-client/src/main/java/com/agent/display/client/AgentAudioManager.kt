package com.agent.display.client

import android.util.Log
import com.agent.display.common.AppAudioKey
import com.agent.display.common.AudioMode
import com.agent.display.common.IAgentShell
import java.io.Closeable
import java.util.concurrent.ConcurrentHashMap

/**
 * 客户端后台应用静音策略管理器。
 *
 * 核心设计：
 * 1. 启动前调用 beforeLaunch 提前进入静音模式，杜绝应用开屏广告与背景音乐爆音；
 * 2. 严谨记录每个应用静音前的原始 AppOps 模式；
 * 3. 支持用户接管与明确解静音；
 * 4. 无论会话正常收尾还是异常释放，统一遵循 AudioMode.calculateRestoreMode 规则，
 *    空或 default 模式安全还原为 "allow"，杜绝在定制系统中留下永久静音的脏状态。
 */
class AgentAudioManager(
    private val shell: IAgentShell,
    private val isAudioMuteEnabled: () -> Boolean = { true }
) : Closeable, AutoCloseable {

    private val mutedRecords = ConcurrentHashMap<AppAudioKey, AudioMode>()

    /**
     * 应用启动前预静音调度：
     * 在真正拉起 Activity 前记录原值并设为 ignore。
     */
    fun beforeLaunch(packageName: String, userId: Int? = null): Boolean {
        if (!isAudioMuteEnabled()) return false
        val key = AppAudioKey(packageName, userId)
        if (mutedRecords.containsKey(key)) return true

        return try {
            val rawPrior = if (userId != null) {
                shell.getAudioModeInUser(packageName, userId)
            } else {
                shell.getAudioMode(packageName)
            }
            val priorMode = AudioMode.fromRaw(rawPrior)

            val muted = if (userId != null) {
                shell.setAudioMutedInUser(packageName, userId, true)
            } else {
                shell.setAudioMuted(packageName, true)
            }

            if (muted) {
                mutedRecords[key] = priorMode
                Log.i(TAG, "Audio muted for $key (prior: $priorMode)")
                true
            } else {
                Log.w(TAG, "Failed to mute audio for $key")
                false
            }
        } catch (t: Throwable) {
            Log.w(TAG, "Error muting audio for $key", t)
            false
        }
    }

    /** 启动被拒或失败时立即恢复声音，避免未开出的应用误留静音 */
    fun onLaunchFailed(packageName: String, userId: Int? = null): Boolean {
        return restorePackage(packageName, userId)
    }

    /** 用户接管或主动开启声音：恢复声音并从受控列表中移除 */
    fun unmute(packageName: String, userId: Int? = null): Boolean {
        return restorePackage(packageName, userId)
    }

    /** 恢复单个应用原有的音频状态 */
    fun restorePackage(packageName: String, userId: Int? = null): Boolean {
        val key = AppAudioKey(packageName, userId)
        val priorMode = mutedRecords.remove(key)
        val targetMode = AudioMode.calculateRestoreMode(priorMode)

        return try {
            val success = if (userId != null) {
                shell.setAudioModeInUser(packageName, userId, targetMode.raw)
            } else {
                shell.setAudioMode(packageName, targetMode.raw)
            }
            Log.i(TAG, "Restored audio for $key to ${targetMode.raw}, success: $success")
            success
        } catch (t: Throwable) {
            Log.w(TAG, "Error restoring audio for $key", t)
            false
        }
    }

    /** 会话结束或释放时恢复所有由本管理器静音的应用 */
    fun restoreAll() {
        val keys = mutedRecords.keys().toList()
        for (key in keys) {
            restorePackage(key.packageName, key.userId)
        }
    }

    override fun close() {
        restoreAll()
    }

    companion object {
        private const val TAG = "AgentAudioManager"
    }
}
