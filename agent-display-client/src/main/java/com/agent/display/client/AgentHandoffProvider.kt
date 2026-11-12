package com.agent.display.client

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import com.agent.display.common.IAgentShell
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * 客户端用于接收服务端 Shell 守护进程递交 IAgentShell Binder 的 ContentProvider 入口。
 *
 * 对应服务端 AgentServerMain 的 deliverToProvider 握手。
 */
open class AgentHandoffProvider : ContentProvider() {

    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        if (method != METHOD_ATTACH) return null
        val binder = extras?.getBinder(KEY_BINDER) ?: return null
        val uid = extras.getInt(KEY_UID, -1)
        val pid = extras.getInt(KEY_PID, -1)

        Log.i(TAG, "Received remote shell binder from uid: $uid, pid: $pid")

        val shell = IAgentShell.Stub.asInterface(binder)
        _remoteShell.value = shell

        // 返回给服务端的响应，包含客户端的令牌供其注册 DeathRecipient
        return Bundle().apply {
            putBinder("clientToken", clientToken)
        }
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0

    companion object {
        private const val TAG = "AgentHandoffProvider"
        private const val METHOD_ATTACH = "attach"
        private const val KEY_BINDER = "binder"
        private const val KEY_UID = "uid"
        private const val KEY_PID = "pid"

        private val clientToken = Binder()
        private val _remoteShell = MutableStateFlow<IAgentShell?>(null)

        /**
         * 当前已连接的 IAgentShell 响应式流。
         * 当服务端上线并成功递交 Binder 时触发更新。
         */
        val remoteShell: StateFlow<IAgentShell?> = _remoteShell.asStateFlow()

        /**
         * 主动注入已有的 IAgentShell 实例（例如从 Shizuku、AIDL ServiceBinding 直接获取时）
         */
        fun setRemoteShell(shell: IAgentShell?) {
            _remoteShell.value = shell
        }
    }
}
