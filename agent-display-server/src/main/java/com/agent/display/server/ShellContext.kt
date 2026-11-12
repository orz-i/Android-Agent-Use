package com.agent.display.server

import android.annotation.SuppressLint
import android.app.Application
import android.app.Instrumentation
import android.content.AttributionSource
import android.content.Context
import android.content.ContextWrapper
import android.content.pm.ApplicationInfo
import android.os.Build

/**
 * Shell 守护进程里的系统上下文伪造实现。
 *
 * 系统服务（DisplayManager, WindowManager, AppOps 等）会严格核验
 * 「调用方包名与 Binder.getCallingUid() 一致」，因此对外必须报 com.android.shell（UID 2000）。
 */
class ShellContext private constructor(base: Context) : ContextWrapper(base) {
    override fun getPackageName(): String = SHELL_PACKAGE
    override fun getOpPackageName(): String = SHELL_PACKAGE
    override fun getAttributionSource(): AttributionSource =
        AttributionSource.Builder(SHELL_UID).setPackageName(SHELL_PACKAGE).build()
    override fun getApplicationContext(): Context = this

    companion object {
        const val SHELL_PACKAGE = "com.android.shell"
        const val SHELL_UID = 2000

        @SuppressLint("PrivateApi", "DiscouragedPrivateApi")
        fun create(): Context {
            val at = Class.forName("android.app.ActivityThread")
            val thread = at.getMethod("currentActivityThread").invoke(null) ?: newActivityThread(at)
            val systemContext = at.getDeclaredMethod("getSystemContext").invoke(thread) as Context
            val ctx = ShellContext(systemContext)

            val mInitialAppField = at.getDeclaredField("mInitialApplication").apply { isAccessible = true }
            if (mInitialAppField.get(thread) == null) {
                runCatching {
                    val app = Instrumentation.newApplication(Application::class.java, ctx)
                    mInitialAppField.set(thread, app)
                }
            }
            return ctx
        }

        @SuppressLint("PrivateApi", "DiscouragedPrivateApi", "SoonBlockedPrivateApi")
        private fun newActivityThread(at: Class<*>): Any {
            val thread = at.getDeclaredConstructor().apply { isAccessible = true }.newInstance()
            at.getDeclaredField("sCurrentActivityThread").apply { isAccessible = true }.set(null, thread)
            at.getDeclaredField("mSystemThread").apply { isAccessible = true }.setBoolean(thread, true)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                runCatching {
                    val cc = Class.forName("android.app.ConfigurationController")
                    val internal = Class.forName("android.app.ActivityThreadInternal")
                    val controller = cc.getDeclaredConstructor(internal).apply { isAccessible = true }.newInstance(thread)
                    at.getDeclaredField("mConfigurationController").apply { isAccessible = true }.set(thread, controller)
                }
            }

            runCatching {
                val abd = Class.forName("android.app.ActivityThread\$AppBindData")
                val data = abd.getDeclaredConstructor().apply { isAccessible = true }.newInstance()
                abd.getDeclaredField("appInfo").apply { isAccessible = true }
                    .set(data, ApplicationInfo().apply { packageName = SHELL_PACKAGE })
                at.getDeclaredField("mBoundApplication").apply { isAccessible = true }.set(thread, data)
            }
            return thread
        }
    }
}
