package com.agent.display.server

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import android.util.Log

class ShellClipboard(private val context: Context) {
    companion object {
        private const val TAG = "ShellClipboard"
        private const val CLIP_LABEL = "Agent"
        private const val EXTRA_IS_SENSITIVE = "android.content.extra.IS_SENSITIVE"
        private const val EXTRA_SUPPRESS_CLIPBOARD_OVERLAY = "com.android.systemui.SUPPRESS_CLIPBOARD_OVERLAY"
    }

    private val cm: ClipboardManager by lazy {
        context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    }

    private val lock = Any()
    private var savedClip: ClipData? = null
    private var clipSaved: Boolean = false
    private var ourText: String? = null

    fun setClipText(text: String): Int = synchronized(lock) {
        try {
            if (!clipSaved) {
                savedClip = runCatching { cm.primaryClip }.getOrNull()
                clipSaved = true
            }
            val clip = ClipData.newPlainText(CLIP_LABEL, text)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                clip.description.extras = (clip.description.extras ?: PersistableBundle()).apply {
                    putBoolean(EXTRA_IS_SENSITIVE, true)
                    putBoolean(EXTRA_SUPPRESS_CLIPBOARD_OVERLAY, true)
                }
            }
            cm.setPrimaryClip(clip)
            ourText = text
            0 // 成功
        } catch (t: Throwable) {
            Log.w(TAG, "setClipText failed", t)
            2 // 失败
        }
    }

    fun restoreClip(): Boolean = synchronized(lock) {
        if (!clipSaved) return true
        return try {
            val current = runCatching { cm.primaryClip?.getItemAt(0)?.text?.toString() }.getOrNull()
            if (current != null && current == ourText) {
                val toRestore = savedClip
                if (toRestore != null) {
                    cm.setPrimaryClip(toRestore)
                } else {
                    cm.clearPrimaryClip()
                }
            }
            savedClip = null
            clipSaved = false
            ourText = null
            true
        } catch (t: Throwable) {
            Log.w(TAG, "restoreClip failed", t)
            false
        }
    }

    fun savedClipText(): String? = synchronized(lock) {
        if (!clipSaved) null else savedClip?.getItemAt(0)?.text?.toString().orEmpty()
    }

    fun restoreClipText(original: String, ours: String): Boolean = synchronized(lock) {
        return try {
            val current = runCatching { cm.primaryClip?.getItemAt(0)?.text?.toString() }.getOrNull()
            if (current != null && current == ours) {
                if (original.isNotEmpty()) {
                    cm.setPrimaryClip(ClipData.newPlainText(CLIP_LABEL, original))
                } else {
                    cm.clearPrimaryClip()
                }
            }
            true
        } catch (t: Throwable) {
            Log.w(TAG, "restoreClipText failed", t)
            false
        }
    }
}
