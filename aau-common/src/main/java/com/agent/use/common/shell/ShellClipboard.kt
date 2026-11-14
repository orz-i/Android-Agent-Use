package com.agent.use.common.shell

import android.annotation.SuppressLint
import android.app.AppOpsManager
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PersistableBundle
import android.os.Process
import android.util.Log
import java.lang.reflect.Method

/**
 * Direct `IClipboard` Binder client + safe swap/restore isolation for `app_process` shell services.
 *
 * Bypasses `ClipboardManager` read paths that trigger extra `Settings` provider queries unsupported
 * in `app_process`, while falling back to `ClipboardManager` if OEM signatures differ.
 */
@SuppressLint("PrivateApi")
class ShellClipboard(
    private val context: Context,
    private val clipLabel: String = DEFAULT_CLIP_LABEL,
) {
    private val manager: ClipboardManager by lazy {
        ClipboardManager::class.java.getDeclaredConstructor(Context::class.java, Handler::class.java)
            .apply { isAccessible = true }
            .newInstance(context, Handler(Looper.getMainLooper() ?: Looper.myLooper()!!))
    }

    private val service: Any? by lazy {
        runCatching {
            val binder = Class.forName("android.os.ServiceManager")
                .getMethod("getService", String::class.java)
                .invoke(null, "clipboard") as IBinder
            Class.forName("android.content.IClipboard\$Stub")
                .getMethod("asInterface", IBinder::class.java)
                .invoke(null, binder)
        }.getOrNull()
    }

    private val getClip by lazy { method("getPrimaryClip") }
    private val getDescription by lazy { method("getPrimaryClipDescription") }
    private val hasClip by lazy { method("hasPrimaryClip") }
    private val callerLabel by lazy {
        runCatching {
            val pm = context.packageManager
            pm.getApplicationLabel(pm.getApplicationInfo(ShellContext.SHELL_PACKAGE, 0)).toString()
        }.getOrDefault(ShellContext.SHELL_PACKAGE)
    }

    private val clipLock = Any()
    private var savedClip: ClipData? = null
    private var clipSaved = false
    private var ourText: String? = null

    val primaryClip: ClipData?
        get() = getClip.let { if (it == null) manager.primaryClip else call(it) as ClipData? }

    val primaryClipDescription: ClipDescription?
        get() = getDescription.let { if (it == null) manager.primaryClipDescription else call(it) as ClipDescription? }

    fun hasPrimaryClip(): Boolean = hasClip.let { if (it == null) manager.hasPrimaryClip() else call(it) as Boolean }

    fun setPrimaryClip(clip: ClipData) = manager.setPrimaryClip(clip)

    fun clearPrimaryClip() = manager.clearPrimaryClip()

    /**
     * Temporarily sets the system clipboard to [text] (suppressing overlay and marking sensitive),
     * saving the user's prior clip first. Refuses if the current clipboard cannot be read safely.
     */
    fun setClipText(text: String): Int = synchronized(clipLock) {
        try {
            if (clipSaved && !restoreClip()) return CLIP_UNREADABLE
            if (!clipSaved) {
                if (!canReadClipboard()) return CLIP_UNREADABLE
                val prior = primaryClip
                when (ShellClip.read(prior != null, hasPrimaryClip(), primaryClipDescription != null)) {
                    ShellClip.Read.Unreadable -> {
                        Log.i(TAG, "setClipText: clip present but unreadable, not replacing")
                        return CLIP_UNREADABLE
                    }
                    ShellClip.Read.Empty -> Log.i(TAG, "setClipText: user clipboard was empty")
                    ShellClip.Read.Has -> Log.i(TAG, "setClipText: user clipboard saved")
                }
                savedClip = prior
                clipSaved = true
            }
            val clip = ClipData.newPlainText(clipLabel, text)
            suppressOverlay(clip)
            markSensitive(clip)
            setPrimaryClip(clip)
            ourText = text
            if (nowState(text) == ShellClip.Now.Ours) CLIP_SET else CLIP_FAILED
        } catch (t: Throwable) {
            Log.w(TAG, "setClipText failed", t)
            CLIP_FAILED
        }
    }

    /** Restores the previously saved user clipboard if it has not been overwritten by the user. */
    fun restoreClip(): Boolean = synchronized(clipLock) {
        if (!clipSaved) return true
        val finished = runCatching {
            val prior = savedClip
            val now = nowState(ourText)
            val action = ShellClip.restore(prior == null, now)
            Log.i(TAG, "restoreClip: now=$now action=$action")
            when (action) {
                ShellClip.Restore.PutBack -> setPrimaryClip(suppressOverlay(prior!!))
                ShellClip.Restore.Clear -> clearPrimaryClip()
                ShellClip.Restore.Leave -> Unit
            }
            val after = nowState(ourText)
            after != ShellClip.Now.Ours && after != ShellClip.Now.Unreadable
        }.onFailure { Log.w(TAG, "restoreClip failed", it) }.getOrDefault(false)
        if (finished) {
            savedClip = null
            clipSaved = false
            ourText = null
        }
        finished
    }

    /** Returns the backed-up plain-text clipboard value (empty string if originally empty), or `null` if none saved. */
    fun savedClipText(): String? = synchronized(clipLock) {
        if (!clipSaved) return null
        runCatching { savedClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString() }.getOrNull().orEmpty()
    }

    /** Restores [original] only when the current clipboard still matches [ours]. */
    fun restoreClipText(original: String, ours: String): Boolean = synchronized(clipLock) {
        runCatching {
            val now = nowState(ours)
            val action = ShellClip.restore(original.isEmpty(), now)
            Log.i(TAG, "restoreClipText: now=$now action=$action")
            when (action) {
                ShellClip.Restore.PutBack -> setPrimaryClip(suppressOverlay(ClipData.newPlainText("", original)))
                ShellClip.Restore.Clear -> clearPrimaryClip()
                ShellClip.Restore.Leave -> Unit
            }
            val after = nowState(ours)
            after != ShellClip.Now.Ours && after != ShellClip.Now.Unreadable
        }.onFailure { Log.w(TAG, "restoreClipText failed", it) }.getOrDefault(false)
    }

    private fun nowState(ours: String?): ShellClip.Now {
        val now = primaryClip
        return when (ShellClip.read(now != null, hasPrimaryClip(), primaryClipDescription != null)) {
            ShellClip.Read.Empty -> ShellClip.Now.Empty
            ShellClip.Read.Unreadable -> ShellClip.Now.Unreadable
            ShellClip.Read.Has -> {
                val ourClip = now!!.description.label == clipLabel &&
                    now.itemCount == 1 &&
                    ours != null &&
                    now.getItemAt(0).text?.toString() == ours
                if (ourClip) ShellClip.Now.Ours else ShellClip.Now.Other
            }
        }
    }

    private fun canReadClipboard(): Boolean = runCatching {
        val granted = context.checkPermission(READ_CLIPBOARD_IN_BACKGROUND, Process.myPid(), Process.myUid()) ==
            PackageManager.PERMISSION_GRANTED
        val ops = context.getSystemService(AppOpsManager::class.java)
        granted && ops.unsafeCheckOpNoThrow(OPSTR_READ_CLIPBOARD, Process.myUid(), ShellContext.SHELL_PACKAGE) ==
            AppOpsManager.MODE_ALLOWED
    }.getOrDefault(false)

    private fun suppressOverlay(clip: ClipData): ClipData {
        val extras = clip.description.extras?.let { PersistableBundle(it) } ?: PersistableBundle()
        extras.putBoolean(EXTRA_SUPPRESS_CLIPBOARD_OVERLAY, true)
        clip.description.extras = extras
        return clip
    }

    private fun markSensitive(clip: ClipData): ClipData {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return clip
        val extras = clip.description.extras?.let { PersistableBundle(it) } ?: PersistableBundle()
        extras.putBoolean(EXTRA_IS_SENSITIVE, true)
        clip.description.extras = extras
        return clip
    }

    private fun method(name: String): Method? {
        if (service == null) return null
        val type = runCatching { Class.forName("android.content.IClipboard") }.getOrNull() ?: return null
        val s = String::class.java
        val i = Int::class.javaPrimitiveType!!
        val candidates = listOf(
            arrayOf(s, s, i, i),
            arrayOf(s, s, i),
            arrayOf(s, s, s, s, i, i, Boolean::class.javaPrimitiveType!!),
        )
        return candidates.firstNotNullOfOrNull { runCatching { type.getMethod(name, *it) }.getOrNull() }
    }

    private fun call(method: Method): Any? {
        val userId = Process.myUid() / 100_000
        val args: Array<Any?> = when (method.parameterTypes.size) {
            7 -> arrayOf(ShellContext.SHELL_PACKAGE, callerLabel, "", null, userId, 0, false)
            4 -> arrayOf(ShellContext.SHELL_PACKAGE, null, userId, 0)
            else -> arrayOf(ShellContext.SHELL_PACKAGE, null, userId)
        }
        return method.invoke(service, *args)
    }

    companion object {
        private const val TAG = "ShellClipboard"
        const val DEFAULT_CLIP_LABEL = "Agent"
        const val CLIP_SET = 0
        const val CLIP_UNREADABLE = 1
        const val CLIP_FAILED = 2
        private const val OPSTR_READ_CLIPBOARD = "android:read_clipboard"
        private const val READ_CLIPBOARD_IN_BACKGROUND = "android.permission.READ_CLIPBOARD_IN_BACKGROUND"
        private const val EXTRA_IS_SENSITIVE = "android.content.extra.IS_SENSITIVE"
        private const val EXTRA_SUPPRESS_CLIPBOARD_OVERLAY = "com.android.systemui.SUPPRESS_CLIPBOARD_OVERLAY"
    }
}
