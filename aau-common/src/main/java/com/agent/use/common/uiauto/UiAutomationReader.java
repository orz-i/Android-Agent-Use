package com.agent.use.common.uiauto;

import android.graphics.Rect;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityWindowInfo;

import org.json.JSONArray;
import org.json.JSONObject;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * 以 shell 身份读当前焦点屏的节点树，不需要注册任何 AccessibilityService。
 *
 * <p>原理：{@code UiAutomation} 是 instrumentation 侧的读屏通道，由系统单独管理，
 * 不会出现在 {@code enabled_accessibility_services} 里，
 * 因此应用侧用 {@code getEnabledAccessibilityServiceList} 看不到它。
 *
 * <p>{@code UiAutomation} 是 @hide 类，这里全程反射调用；
 * 它的连接按线程绑定，所以所有调用都收敛到主线程。
 *
 * <p>节点树以扁平 JSON 返回，用 {@code parent} 指向父节点的下标，避免嵌套过深和重复字段。
 */
public final class UiAutomationReader {

    private static final String TAG = "UiAutomationReader";
    /** 不抑制已有的无障碍服务，避免打断 Mika 自己的服务。 */
    private static final int FLAG_DONT_SUPPRESS = 0x1;
    /**
     * 连接失败后的冷却时间。原来给 60 秒，结果一次瞬时失败（无障碍服务正被重启、system_server 刚起来）
     * 就会让整条通道瘫一分钟，读屏全落空。这里只挡住"连续重试打爆 Binder"，隔一会儿照常再试。
     */
    private static final long RETRY_MS = 2_000L;
    private static final int TIMEOUT_SEC = 5;

    private final Handler main = new Handler(Looper.getMainLooper());
    private Object automation;
    private Method rootInActiveWindow;
    private Method getWindows;
    private boolean broken;
    private long brokenAt;
    /** 最近一次连接失败的原因，随 {"ok":false} 一起返回，省得再去翻进程日志。 */
    private String lastError;

    /**
     * 读一次屏。返回的 JSON 结构：
     * <pre>
     * {"ok":true,"pkg":"...","display":8,"count":72,"nodes":[
     *   {"parent":-1,"cls":"...","text":"...","desc":"...","id":"...",
     *    "l":0,"t":0,"r":720,"b":1280,"click":1,"edit":0,"scroll":1,"vis":1}
     * ]}
     * </pre>
     * 失败时返回 {@code {"ok":false,"reason":"..."}}。
     */
    public String dump(int maxDepth, int maxNodes) {
        if (Looper.myLooper() == Looper.getMainLooper()) return dumpOnMain(maxDepth, maxNodes);
        final String[] out = new String[1];
        final CountDownLatch latch = new CountDownLatch(1);
        main.post(() -> {
            try {
                out[0] = dumpOnMain(maxDepth, maxNodes);
            } finally {
                latch.countDown();
            }
        });
        try {
            if (!latch.await(TIMEOUT_SEC, TimeUnit.SECONDS)) return error("timeout");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return error("interrupted");
        }
        return out[0] != null ? out[0] : error("empty");
    }

    /** 主动断开，进程退出前调用。 */
    public void close() {
        if (automation == null) return;
        try {
            automation.getClass().getMethod("disconnect").invoke(automation);
        } catch (Throwable t) {
            Log.w(TAG, "disconnect failed", t);
        }
        automation = null;
        rootInActiveWindow = null;
    }

    private String dumpOnMain(int maxDepth, int maxNodes) {
        if (!ensureConnected()) {
            return error(broken && lastError != null ? "connect:" + lastError : "connect");
        }
        AccessibilityNodeInfo root = null;
        try {
            root = (AccessibilityNodeInfo) rootInActiveWindow.invoke(automation);
        } catch (Throwable t) {
            Log.w(TAG, "getRootInActiveWindow failed", t);
            markBroken();
            return error("root");
        }
        if (root == null) return error("noroot");
        try {
            JSONArray nodes = new JSONArray();
            walk(root, -1, 0, maxDepth, maxNodes, nodes);
            JSONObject out = new JSONObject();
            out.put("ok", true);
            out.put("pkg", root.getPackageName() == null ? "" : root.getPackageName().toString());
            out.put("display", displayOf(root));
            out.put("count", nodes.length());
            out.put("nodes", nodes);
            out.put("windows", windowsJson());
            return out.toString();
        } catch (Throwable t) {
            Log.w(TAG, "serialize failed", t);
            return error("serialize");
        } finally {
            root.recycle();
        }
    }

    /**
     * 节点所在屏幕。根节点有时拿不到窗口信息，往下找几层；
     * 都取不到返回 -1（调用方需容忍，用包名或屏幕尺寸自行判断）。
     */
    private int displayOf(AccessibilityNodeInfo root) {
        AccessibilityNodeInfo cur = root;
        for (int depth = 0; depth < 4 && cur != null; depth++) {
            try {
                AccessibilityWindowInfo w = cur.getWindow();
                if (w != null) {
                    int id = w.getDisplayId();
                    if (id >= 0) return id;
                }
            } catch (Throwable ignored) {
            }
            try {
                cur = cur.getChild(0);
            } catch (Throwable ignored) {
                return -1;
            }
        }
        return -1;
    }

    /**
     * 活动窗口一览：屏号、类型、是否焦点、根节点包名与尺寸。
     *
     * <p>诊断用，也是"虚拟屏不是焦点屏"时的备选入口：窗口列表里看得到目标屏的窗口，
     * 就能从那个窗口的根节点读树，不必去抢焦点。
     */
    private JSONArray windowsJson() {
        JSONArray arr = new JSONArray();
        if (getWindows == null) return arr;
        try {
            Object list = getWindows.invoke(automation);
            if (!(list instanceof List)) return arr;
            for (Object item : (List<?>) list) {
                if (!(item instanceof AccessibilityWindowInfo)) continue;
                AccessibilityWindowInfo w = (AccessibilityWindowInfo) item;
                JSONObject j = new JSONObject();
                try {
                    j.put("d", w.getDisplayId());
                    j.put("t", w.getType());
                    j.put("f", w.isFocused() ? 1 : 0);
                    j.put("a", w.isActive() ? 1 : 0);
                    AccessibilityNodeInfo r = null;
                    try {
                        r = w.getRoot();
                    } catch (Throwable ignored) {
                    }
                    if (r != null) {
                        CharSequence pkg = r.getPackageName();
                        j.put("pkg", pkg == null ? "" : pkg.toString());
                        Rect b = new Rect();
                        r.getBoundsInScreen(b);
                        j.put("w", b.width());
                        j.put("h", b.height());
                        j.put("n", r.getChildCount());
                        r.recycle();
                    }
                } catch (Throwable ignored) {
                }
                arr.put(j);
            }
        } catch (Throwable t) {
            Log.w(TAG, "getWindows failed", t);
        }
        return arr;
    }

    private void walk(
            AccessibilityNodeInfo n, int parent, int depth, int maxDepth, int maxNodes, JSONArray out) {
        if (n == null || depth > maxDepth || out.length() >= maxNodes) return;
        int index = out.length();
        try {
            JSONObject o = new JSONObject();
            o.put("parent", parent);
            Rect r = new Rect();
            n.getBoundsInScreen(r);
            o.put("l", r.left);
            o.put("t", r.top);
            o.put("r", r.right);
            o.put("b", r.bottom);
            put(o, "cls", n.getClassName());
            put(o, "text", n.getText());
            put(o, "desc", n.getContentDescription());
            put(o, "id", n.getViewIdResourceName());
            put(o, "hint", n.getHintText());
            o.put("click", n.isClickable() ? 1 : 0);
            o.put("edit", n.isEditable() ? 1 : 0);
            o.put("scroll", n.isScrollable() ? 1 : 0);
            o.put("vis", n.isVisibleToUser() ? 1 : 0);
            o.put("focus", n.isFocused() ? 1 : 0);
            o.put("sel", n.isSelected() ? 1 : 0);
            o.put("en", n.isEnabled() ? 1 : 0);
            o.put("pwd", n.isPassword() ? 1 : 0);
            o.put("chk", n.isCheckable() ? (n.isChecked() ? 2 : 1) : 0);
            out.put(o);
        } catch (Throwable t) {
            // 单个节点序列化失败不影响整棵树
            return;
        }
        int count = n.getChildCount();
        for (int i = 0; i < count; i++) {
            AccessibilityNodeInfo child = null;
            try {
                child = n.getChild(i);
            } catch (Throwable t) {
                continue;
            }
            if (child == null) continue;
            walk(child, index, depth + 1, maxDepth, maxNodes, out);
            child.recycle();
        }
    }

    private static void put(JSONObject o, String key, CharSequence value) {
        if (value == null) return;
        String s = value.toString();
        if (s.isEmpty()) return;
        try {
            o.put(key, s);
        } catch (Throwable ignored) {
        }
    }

    private boolean ensureConnected() {
        if (automation != null) return true;
        long now = System.currentTimeMillis();
        if (broken && now - brokenAt < RETRY_MS) return false;
        try {
            connect();
            broken = false;
            lastError = null;
            Log.i(TAG, "ui automation connected");
            return true;
        } catch (Throwable t) {
            Log.w(TAG, "ui automation connect failed", t);
            lastError = describe(t);
            markBroken();
            return false;
        }
    }

    /** 异常压成一行:类名 + 消息,反射失败时把被包住的那个也带上。 */
    private static String describe(Throwable t) {
        StringBuilder sb = new StringBuilder(t.getClass().getSimpleName());
        if (t.getMessage() != null) sb.append(": ").append(t.getMessage());
        Throwable cause = t.getCause();
        for (int depth = 0; cause != null && depth < 3; depth++) {
            sb.append(" <- ").append(cause.getClass().getSimpleName());
            if (cause.getMessage() != null) sb.append(": ").append(cause.getMessage());
            cause = cause.getCause();
        }
        return sb.toString().replace('"', '\'').replace('\n', ' ');
    }

    private void connect() throws Exception {
        Class<?> uaCls = Class.forName("android.app.UiAutomation");
        Class<?> connCls = Class.forName("android.app.UiAutomationConnection");
        Constructor<?> connCtor = connCls.getDeclaredConstructor();
        connCtor.setAccessible(true);
        Object connection = connCtor.newInstance();

        Object instance = null;
        for (Constructor<?> ctor : uaCls.getDeclaredConstructors()) {
            Class<?>[] params = ctor.getParameterTypes();
            if (params.length < 2 || !params[0].getName().equals("android.os.Looper")) continue;
            if (!params[1].isInstance(connection)) continue;
            Object[] args = new Object[params.length];
            args[0] = Looper.getMainLooper();
            args[1] = connection;
            for (int i = 2; i < params.length; i++) {
                Class<?> p = params[i];
                args[i] = p == boolean.class ? Boolean.FALSE : p == int.class ? Integer.valueOf(0) : null;
            }
            ctor.setAccessible(true);
            instance = ctor.newInstance(args);
            break;
        }
        if (instance == null) throw new IllegalStateException("no UiAutomation constructor");

        uaCls.getMethod("connect", int.class).invoke(instance, FLAG_DONT_SUPPRESS);
        automation = instance;
        rootInActiveWindow = uaCls.getMethod("getRootInActiveWindow");
        // getRootInActiveWindow 只给"焦点屏"的根。Mika 的虚拟屏不是焦点屏时什么也读不到,
        // getWindows 是另一条能列出活动窗口的路(哪怕跨屏),先留着——能不能用由调用方按返回内容判断。
        try {
            getWindows = uaCls.getMethod("getWindows");
        } catch (Throwable t) {
            getWindows = null;
            Log.i(TAG, "getWindows not available: " + describe(t));
        }
    }

    private void markBroken() {
        broken = true;
        brokenAt = System.currentTimeMillis();
        automation = null;
        rootInActiveWindow = null;
        getWindows = null;
    }

    private static String error(String reason) {
        return "{\"ok\":false,\"reason\":\"" + reason + "\"}";
    }
}
