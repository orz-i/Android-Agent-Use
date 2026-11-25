package com.agent.use.ui

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt

/** 像素坐标换成 0–999 的端口坐标,与反算互逆:n = round(p*999/(size-1)),夹在 0–999。 */
fun normalize(p: Int, size: Int): Int {
    if (size <= 1) return 0
    return min(999, max(0, (p * 999.0 / (size - 1)).roundToInt()))
}

/**
 * 屏幕上的一个元素。ref 形如 "@e3";center 为像素(端口内部用,交给模型前换成 0–999);bounds 为 [l,t,r,b],已归一到 0–999。
 * [hint]:输入框里显示的是提示语/预置词(name 就是它),不是已经输入的内容。
 * [focused]:有输入焦点(回车、空格作用在它上面)。
 * [secret]:密码框。
 * [placeholder]:输入框自己的提示语(打了字之后也还在,和此刻显示的 [name] 无关);没有为 null。
 * [searchField]:控件按自己的语义就是搜索框(网页的 type=search、role=searchbox、回车键标成搜索;安卓的搜索框控件)。
 * [states]:控件此刻为真的状态([UiStates] 里的名字:选中、勾上、展开、按下、不可用);判动作效果时开关一拨就看得出。
 */
data class UiElement(
    val ref: String,
    val role: String,
    val name: String,
    val centerX: Int,
    val centerY: Int,
    val bounds: List<Int>,
    val resourceId: String?,
    val clickable: Boolean,
    val editable: Boolean,
    val scrollable: Boolean,
    val hint: Boolean = false,
    val focused: Boolean = false,
    /** 网页上页面声明给这个控件的快捷键(aria-keyshortcuts、accesskey 换成 Alt+键)。 */
    val keyShortcuts: List<String> = emptyList(),
    val secret: Boolean = false,
    val placeholder: String? = null,
    val searchField: Boolean = false,
    val states: Set<String> = emptySet(),
) {
    /** 无名字且不可交互的节点对模型没有信息量。 */
    val meaningful: Boolean get() = name.isNotBlank() || clickable || editable || scrollable
}

/** 控件状态的名字,手机与网页共用。 */
object UiStates {
    const val CHECKED = "checked"
    const val SELECTED = "selected"
    const val EXPANDED = "expanded"
    const val PRESSED = "pressed"
    const val DISABLED = "disabled"
    val ALL = setOf(CHECKED, SELECTED, EXPANDED, PRESSED, DISABLED)
}

/**
 * 一屏的读屏结果(纯数据,不含端口)。
 *
 * [changedDuringRead]:读这份列表的前后界面不一致(页面自己在动),列表可能和屏幕对不上。
 * [protected]:有明确依据认定当前页面受系统防截屏保护,画面看不到。
 * [captureError]:画面不能作为当前内容使用,但没有依据断言是防截屏;值是通用错误码。
 * 此时仍可使用读到的无障碍元素,不能把黑帧或旧帧交给视觉模型。
 * [hasWindow]:屏上有 App 窗口(根节点读不读得到都算);为 false 且没有元素时才是真正的空屏。
 * [web]:网页读屏时的页面信息;手机读屏时为空。
 * [unreadableApp]:读不到窗口内容(安全窗口、启动画面、显示在别处),但端口按焦点窗口或最上面的任务知道前台是哪个 App 时,
 * 它的包名;读得到或不知道时为 null。有它时「没有元素」不等于「没打开 App」。
 */
data class ScreenSnapshot(
    val snapshotId: String,
    val packageName: String?,
    val elements: List<UiElement>,
    val width: Int,
    val height: Int,
    val changedDuringRead: Boolean = false,
    val protected: Boolean = false,
    val hasWindow: Boolean = true,
    val web: WebInfo? = null,
    val unreadableApp: String? = null,
    /** 手机无障碍窗口的完整可见层级;网页和测试端口可不提供。 */
    val windows: List<UiWindowTree> = emptyList(),
    /** 上一个动作过后才开到用户主屏上、读这一屏前刚挪回来的 App(见 [OpenedElsewhere]);没有为 null。 */
    val opened: OpenedElsewhere? = null,
    /** 画面不可用但不是已证实的防截屏;见上方 [captureError] 说明。 */
    val captureError: String? = null,
    /** 当前前台 Activity 名（如 `com.pkg/.MainActivity`）；网页或取不到时为 null。 */
    val activity: String? = null,
    /** 页面结构签名（用于离线建图与页面匹配）；网页、受保护屏或未提取时为 null。 */
    val screenSig: ScreenSig? = null,
) {
    /** 补齐包名与 Activity 元信息后的有效页面签名；空白或受保护屏返回 null。 */
    fun resolvedScreenSig(): ScreenSig? {
        if (protected) return null
        val sig = screenSig?.takeUnless { it.isBlank } ?: return null
        val act = sig.activity ?: activity
        val pkg = sig.packageName ?: packageName
        val shortAct = sig.shortActivity ?: ScreenSig.shortActivityName(pkg, act)
        return if (act == sig.activity && pkg == sig.packageName && shortAct == sig.shortActivity) sig
        else sig.copy(activity = act, packageName = pkg, shortActivity = shortAct)
    }
}

/**
 * 动作让一个 App 开到了 Agent 的屏以外、用户的主屏上(App 不是从自己在 Agent 屏上的页面里打开它,系统就放到了主屏)。
 * [packageName] 那个 App(系统问打开哪一个时是问的那个窗口所在的包),[app] 它的显示名。
 * [pulledBack]:已挪到 Agent 的屏、在最上面;为 false 时它留在用户的主屏上没动(用户正用着的那个 App,或系统在问用户)。
 * [inProfile]:这个 App 装了两份(分身、工作资料)时开的是哪一份,[MAIN_PROFILE] 本来那份、[OTHER_PROFILE] 另一份;只装了一份或看不出为 null。
 * [picker]:开出来的是系统问「用哪一个打开」的窗口。它从不挪:留给用户在自己屏上选,选之前任务停着等;[app] 是问的那个 App 的名字。
 * [closed]:用户把那个问题关了,什么也没打开。[byUser]:选出来的 App 要用户亲手处理,用户在自己屏上处理完、点了继续。
 * [needsUser]:冒到主屏上的是要用户亲手处理的弹窗(登录验证、账号确认、付款确认一类),留在主屏给他们点。
 */
data class OpenedElsewhere(
    val packageName: String, val app: String?, val pulledBack: Boolean, val inProfile: String? = null, val picker: Boolean = false,
    val closed: Boolean = false, val byUser: Boolean = false, val needsUser: Boolean = false,
    val jumpConfirm: JumpConfirmSummary? = null,
) {
    /** 此刻还在用户的主屏上(用户正用着,或系统正在问用户)。 */
    val onUserScreen: Boolean
        get() = !pulledBack && !closed && !byUser &&
            jumpConfirm?.choice != JumpConfirmSummary.DENY &&
            jumpConfirm?.outcome != JumpConfirmSummary.AUTO_ALLOWED &&
            jumpConfirm?.outcome != JumpConfirmSummary.USER_ALLOWED

    fun toJson(): JsonObject = buildJsonObject {
        put("package", packageName)
        app?.let { put("app", it) }
        put("pulledBack", pulledBack)
        if (onUserScreen) put("onUserScreen", true)
        if (needsUser) put("needsUser", true)
        inProfile?.let { put("inProfile", it) }
        if (picker) put("picker", true)
        if (closed) put("closed", true)
        if (byUser) put("byUser", true)
        jumpConfirm?.let { jc ->
            put("jumpConfirm", buildJsonObject {
                jc.initiator?.let { put("initiator", it) }
                jc.target?.let { put("target", it) }
                jc.by?.let { put("by", it) }
                put("choice", jc.choice)
                put("outcome", jc.outcome)
                jc.degradeReason?.let { put("degradeReason", it) }
            })
        }
    }

    companion object {
        const val MAIN_PROFILE = "main"
        const val OTHER_PROFILE = "other"
    }
}

/**
 * 系统跳转授权一类弹窗的处理摘要。字段都是协议码,不是枚举:各宿主自己的护栏编号与原因码原样带过来,
 * 库不解释、也不定义策略。
 *
 * [by] agent / user;[choice] allow / deny / unknown;[outcome] waiting_user / auto_allowed / user_allowed / denied / unavailable。
 * 给模型看的话只从 [choice] 与 [outcome] 判断,不给它看原因码。
 */
data class JumpConfirmSummary(
    val initiator: String?,
    val target: String?,
    val by: String? = null,
    val choice: String = UNKNOWN,
    val outcome: String = WAITING_USER,
    val degradeReason: String? = null,
) {
    companion object {
        const val BY_AGENT = "agent"
        const val BY_USER = "user"
        const val ALLOW = "allow"
        const val DENY = "deny"
        const val UNKNOWN = "unknown"
        const val WAITING_USER = "waiting_user"
        const val AUTO_ALLOWED = "auto_allowed"
        const val USER_ALLOWED = "user_allowed"
        const val DENIED = "denied"
        const val UNAVAILABLE = "unavailable"
    }
}

/** 从当前任务的虚拟屏收到的界面事件；通知事件可以来自整台设备。 */
data class ScreenEvent(val type: String, val packageName: String?, val text: String?)

/** 本机 OCR 从当前屏幕图像读出的文字行，边界采用与无障碍元素相同的 0–999 坐标；[confidence] 是识别给的 0–1 置信度。 */
data class VisibleTextLine(val text: String, val bounds: List<Int>, val confidence: Float? = null)

/** 输入后读回输入框的核对结果;读不回来(密码框、读不到节点)为 UNKNOWN。 */
enum class Verification(val wire: String) { MATCH("match"), MISMATCH("mismatch"), UNKNOWN("unknown") }
