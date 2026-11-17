package com.agent.use.a11y

import com.agent.use.a11y.model.A11yNode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ScreenSignatureTest {

    @Test
    fun testShortAndNormalizedActivityNames() {
        assertEquals("LauncherUI", shortActivityName("com.tencent.mm", "com.tencent.mm/.ui.LauncherUI"))
        assertEquals("LauncherUI", shortActivityName("com.tencent.mm", "com.tencent.mm/com.tencent.mm.ui.LauncherUI"))
        assertEquals("LauncherUI", shortActivityName("com.tencent.mm", "com.tencent.mm.ui.LauncherUI"))
        assertEquals("MainActivity", shortActivityName("com.example", ".MainActivity"))
        assertEquals("MainActivity", shortActivityName(null, "com.example/.MainActivity"))
        assertEquals("MainActivity", shortActivityName("com.example", "MainActivity"))
        assertNull(shortActivityName("com.example", null))
        assertNull(shortActivityName("com.example", "   "))
        assertNull(shortActivityName("com.example", "com.example"))

        val n1 = ScreenSignature.normalizeActivityName("com.tencent.mm", "com.tencent.mm/.ui.LauncherUI")
        val n2 = ScreenSignature.normalizeActivityName("com.tencent.mm", "com.tencent.mm/com.tencent.mm.ui.LauncherUI")
        val n3 = ScreenSignature.normalizeActivityName("com.tencent.mm", "com.tencent.mm.ui.LauncherUI")
        val n4 = ScreenSignature.normalizeActivityName("com.tencent.mm", ".ui.LauncherUI")
        assertEquals("com.tencent.mm/com.tencent.mm.ui.LauncherUI", n1)
        assertEquals(n1, n2)
        assertEquals(n1, n3)
        assertEquals(n1, n4)
    }

    @Test
    fun testSamePageWithDynamicListContentAndUnreadBadgesMatches() {
        val chatTabA = buildWeChatTab(
            title = "微信(3)",
            selectedIndex = 0,
            bottomBadgeFirstTab = "微信(3)",
            listResourceId = "com.tencent.mm:id/conversation_list",
            listItems = listOf(
                "张三" to "晚上吃什么？ 18:05",
                "产品群" to "[2条] 需求评审改到明天 昨天",
            ),
            unreadBadgeOverlay = "99+",
        )

        val chatTabB = buildWeChatTab(
            title = "微信(12)",
            selectedIndex = 0,
            bottomBadgeFirstTab = "微信 (99+)",
            listResourceId = "com.tencent.mm:id/conversation_list",
            listItems = listOf(
                "李四" to "收到，已处理 19:22",
                "快递通知" to "您的包裹已签收 2小时前",
                "测试群(18)" to "打包完成 刚刚",
            ),
            unreadBadgeOverlay = "5",
        )

        val sigA = ScreenSignatureExtractor.extract(
            root = chatTabA,
            packageName = "com.tencent.mm",
            activityName = "com.tencent.mm/.ui.LauncherUI",
            screenWidth = 1080,
            screenHeight = 2400,
        )
        val sigB = ScreenSignatureExtractor.extract(
            root = chatTabB,
            packageName = "com.tencent.mm",
            activityName = "com.tencent.mm.ui.LauncherUI",
            screenWidth = 1080,
            screenHeight = 2400,
        )

        assertFalse(sigA.isBlank)
        assertFalse(sigB.isBlank)
        assertEquals("LauncherUI", sigA.shortActivity)
        assertEquals(sigA.fingerprint, sigB.fingerprint)
        assertEquals(1.0, sigA.similarity(sigB), 0.001)
        assertTrue(sigA.matches(sigB))

        // 确保动态列表内容与未读数不会进入静态锚点
        assertTrue("微信" in sigA.anchors)
        assertFalse(sigA.anchors.any { "张三" in it || "18:05" in it || "99+" in it || "(3)" in it })
        assertFalse(sigB.anchors.any { "李四" in it || "19:22" in it || "昨天" in it || "刚刚" in it })
        assertEquals(listOf("conversation_list", "plus_btn", "search_btn", "tab_chats", "tab_contacts", "tab_discover", "tab_me"), sigA.resourceIds)
    }

    @Test
    fun testDifferentTabsInSameLauncherUiActivityDoNotMatch() {
        val chats = ScreenSignatureExtractor.extract(
            root = buildWeChatTab(
                title = "微信",
                selectedIndex = 0,
                listResourceId = "com.tencent.mm:id/conversation_list",
                listItems = listOf("张三" to "你好"),
            ),
            packageName = "com.tencent.mm",
            activityName = "com.tencent.mm/.ui.LauncherUI",
            screenWidth = 1080,
            screenHeight = 2400,
        )

        val contacts = ScreenSignatureExtractor.extract(
            root = buildWeChatTab(
                title = "通讯录",
                selectedIndex = 1,
                listResourceId = "com.tencent.mm:id/contact_list",
                listItems = listOf("Alice" to "", "Bob" to ""),
                extraTopAction = "添加朋友" to "com.tencent.mm:id/add_friend_btn",
            ),
            packageName = "com.tencent.mm",
            activityName = "com.tencent.mm/.ui.LauncherUI",
            screenWidth = 1080,
            screenHeight = 2400,
        )

        val discover = ScreenSignatureExtractor.extract(
            root = buildWeChatTab(
                title = "发现",
                selectedIndex = 2,
                listResourceId = "com.tencent.mm:id/discover_list",
                listItems = listOf("朋友圈" to "", "扫一扫" to ""),
            ),
            packageName = "com.tencent.mm",
            activityName = "com.tencent.mm/.ui.LauncherUI",
            screenWidth = 1080,
            screenHeight = 2400,
        )

        val me = ScreenSignatureExtractor.extract(
            root = buildWeChatTab(
                title = "我",
                selectedIndex = 3,
                listResourceId = "com.tencent.mm:id/me_list",
                listItems = listOf("服务" to "", "设置" to ""),
                extraHeaderButton = "状态" to "com.tencent.mm:id/status_btn",
            ),
            packageName = "com.tencent.mm",
            activityName = "com.tencent.mm/.ui.LauncherUI",
            screenWidth = 1080,
            screenHeight = 2400,
        )

        val tabs = listOf(chats, contacts, discover, me)
        for (i in tabs.indices) {
            for (j in i + 1 until tabs.size) {
                val sim = tabs[i].similarity(tabs[j])
                assertFalse(
                    "Tabs $i and $j should NOT match (similarity=$sim)",
                    tabs[i].matches(tabs[j]),
                )
                assertTrue("Expected similarity < 0.78 but was $sim", sim < 0.78)
            }
        }
    }

    @Test
    fun testSingleActivityTabsWithoutSelectedFlagOrResourceIdsStillSeparate() {
        // 极端单 Activity（如未设置 selected 且无 resourceId 的 Flutter/Compose 标签页）
        fun customTab(title: String, listHint: String): ScreenSignature {
            val root = ScreenNodeDescriptor(
                role = "FrameLayout",
                bounds = ScreenBounds(0, 0, 1080, 2400),
                children = listOf(
                    ScreenNodeDescriptor(role = "TextView", text = title, bounds = ScreenBounds(40, 80, 280, 150)),
                    ScreenNodeDescriptor(role = "Button", text = "搜索", bounds = ScreenBounds(820, 80, 940, 150), clickable = true),
                    ScreenNodeDescriptor(role = "Button", text = "更多", bounds = ScreenBounds(950, 80, 1050, 150), clickable = true),
                    ScreenNodeDescriptor(
                        role = "View",
                        scrollable = true,
                        bounds = ScreenBounds(0, 180, 1080, 2140),
                        children = listOf(
                            ScreenNodeDescriptor(role = "TextView", text = listHint, bounds = ScreenBounds(40, 240, 500, 320)),
                        ),
                    ),
                    // 底部 4 个未标记 selected 的导航按钮
                    ScreenNodeDescriptor(role = "Button", text = "微信", bounds = ScreenBounds(0, 2160, 270, 2380), clickable = true),
                    ScreenNodeDescriptor(role = "Button", text = "通讯录", bounds = ScreenBounds(270, 2160, 540, 2380), clickable = true),
                    ScreenNodeDescriptor(role = "Button", text = "发现", bounds = ScreenBounds(540, 2160, 810, 2380), clickable = true),
                    ScreenNodeDescriptor(role = "Button", text = "我", bounds = ScreenBounds(810, 2160, 1080, 2380), clickable = true),
                ),
            )
            return ScreenSignatureExtractor.extract(
                root = root,
                packageName = "com.custom.single",
                activityName = "com.custom.single/.MainActivity",
                screenWidth = 1080,
                screenHeight = 2400,
            )
        }

        val tabChats = customTab("微信", "张三: 你好")
        val tabContacts = customTab("通讯录", "Alice")
        assertFalse(tabChats.matches(tabContacts))
        assertTrue("Expected < 0.80, was ${tabChats.similarity(tabContacts)}", tabChats.similarity(tabContacts) < 0.80)
    }

    @Test
    fun testEditableUserInputAndPasswordsIgnoredWhilePlaceholdersPreserved() {
        fun searchScreen(typedQuery: String, passwordDraft: String): ScreenSignature {
            val root = ScreenNodeDescriptor(
                role = "LinearLayout",
                bounds = ScreenBounds(0, 0, 1080, 2400),
                children = listOf(
                    ScreenNodeDescriptor(role = "ImageButton", contentDescription = "返回", resourceId = "com.shop:id/back_btn", bounds = ScreenBounds(20, 60, 120, 160), clickable = true),
                    ScreenNodeDescriptor(
                        role = "EditText",
                        text = typedQuery,
                        hintText = "搜索商品",
                        isHint = false,
                        resourceId = "com.shop:id/search_input",
                        bounds = ScreenBounds(140, 60, 900, 160),
                        clickable = true,
                        editable = true,
                    ),
                    ScreenNodeDescriptor(role = "Button", text = "搜索", resourceId = "com.shop:id/search_submit", bounds = ScreenBounds(920, 60, 1060, 160), clickable = true),
                    ScreenNodeDescriptor(
                        role = "EditText",
                        text = passwordDraft,
                        hintText = "安全口令",
                        password = true,
                        editable = true,
                        bounds = ScreenBounds(140, 200, 900, 280),
                    ),
                    ScreenNodeDescriptor(role = "TextView", text = "综合", bounds = ScreenBounds(60, 320, 200, 390), clickable = true, selected = true),
                    ScreenNodeDescriptor(role = "TextView", text = "销量", bounds = ScreenBounds(260, 320, 400, 390), clickable = true),
                    ScreenNodeDescriptor(
                        role = "RecyclerView",
                        resourceId = "com.shop:id/result_recycler",
                        scrollable = true,
                        bounds = ScreenBounds(0, 420, 1080, 2380),
                        children = listOf(
                            ScreenNodeDescriptor(role = "TextView", text = "$typedQuery 旗舰版 ¥1999.00", bounds = ScreenBounds(40, 460, 800, 560)),
                        ),
                    ),
                ),
            )
            return ScreenSignatureExtractor.extract(
                root = root,
                packageName = "com.shop",
                activityName = "com.shop/.MainActivity",
                screenWidth = 1080,
                screenHeight = 2400,
            )
        }

        val sig1 = searchScreen("蓝牙耳机", "SecretPass1")
        val sig2 = searchScreen("机械键盘", "AnotherPass99")

        assertEquals(sig1.fingerprint, sig2.fingerprint)
        assertTrue(sig1.matches(sig2))
        assertTrue("搜索商品" in sig1.anchors)
        assertTrue("安全口令" in sig1.anchors)
        assertFalse(sig1.anchors.any { "蓝牙" in it || "Secret" in it || "1999" in it })
        assertFalse(sig2.anchors.any { "机械" in it || "Another" in it })
    }

    @Test
    fun testViewPagerAndHorizontalTabsPreservedWhileFlatListFiltered() {
        val nested = ScreenNodeDescriptor(
            role = "FrameLayout",
            bounds = listOf(0, 0, 1000, 1000),
            children = listOf(
                ScreenNodeDescriptor(
                    role = "HorizontalScrollView",
                    scrollable = true,
                    bounds = listOf(0, 20, 1000, 110),
                    children = listOf(
                        ScreenNodeDescriptor(role = "TextView", text = "推荐", bounds = listOf(50, 30, 200, 90), clickable = true, selected = true),
                        ScreenNodeDescriptor(role = "TextView", text = "关注", bounds = listOf(250, 30, 400, 90), clickable = true),
                    ),
                ),
                ScreenNodeDescriptor(
                    role = "ViewPager2",
                    scrollable = true,
                    bounds = listOf(0, 120, 1000, 980),
                    children = listOf(
                        ScreenNodeDescriptor(role = "Button", text = "发布动态", resourceId = "com.sns:id/post_btn", bounds = listOf(780, 820, 960, 940), clickable = true),
                        ScreenNodeDescriptor(
                            role = "RecyclerView",
                            resourceId = "com.sns:id/feed_list",
                            scrollable = true,
                            bounds = listOf(0, 120, 1000, 800),
                            children = listOf(
                                ScreenNodeDescriptor(role = "TextView", text = "动态标题A", bounds = listOf(40, 200, 500, 280)),
                            ),
                        ),
                    ),
                ),
            ),
        )

        val flatSame = listOf(
            ScreenNodeDescriptor(role = "TextView", text = "推荐", bounds = listOf(50, 30, 200, 90), clickable = true, selected = true),
            ScreenNodeDescriptor(role = "TextView", text = "关注", bounds = listOf(250, 30, 400, 90), clickable = true),
            ScreenNodeDescriptor(role = "Button", text = "发布动态", resourceId = "com.sns:id/post_btn", bounds = listOf(780, 820, 960, 940), clickable = true),
            ScreenNodeDescriptor(role = "RecyclerView", resourceId = "com.sns:id/feed_list", scrollable = true, bounds = listOf(0, 120, 1000, 800)),
            // 位于 RecyclerView 矩形内部的扁平条目，应被几何过滤掉
            ScreenNodeDescriptor(role = "TextView", text = "另一条动态内容", bounds = listOf(40, 200, 500, 280)),
        )

        val sigNested = ScreenSignatureExtractor.extract(nested, packageName = "com.sns", activityName = ".MainActivity", screenWidth = 1000, screenHeight = 1000)
        val sigFlat = ScreenSignatureExtractor.extract(flatSame, packageName = "com.sns", activityName = ".MainActivity", screenWidth = 1000, screenHeight = 1000)

        assertTrue("推荐" in sigNested.anchors)
        assertTrue("关注" in sigNested.anchors)
        assertTrue("发布动态" in sigNested.anchors)
        assertFalse("动态标题A" in sigNested.anchors)
        assertFalse("另一条动态内容" in sigFlat.anchors)
        assertEquals(sigNested.fingerprint, sigFlat.fingerprint)
        assertTrue(sigNested.matches(sigFlat))
    }

    @Test
    fun testFloatingActionButtonSiblingOverRecyclerViewPreservedInTree() {
        val tree = ScreenNodeDescriptor(
            role = "FrameLayout",
            bounds = ScreenBounds(0, 0, 1080, 2400),
            children = listOf(
                ScreenNodeDescriptor(role = "TextView", text = "笔记", bounds = ScreenBounds(40, 80, 240, 150)),
                ScreenNodeDescriptor(
                    role = "RecyclerView",
                    resourceId = "com.notes:id/notes_list",
                    scrollable = true,
                    bounds = ScreenBounds(0, 180, 1080, 2380),
                    children = listOf(
                        ScreenNodeDescriptor(role = "TextView", text = "机密会议纪要", bounds = ScreenBounds(40, 220, 600, 300)),
                    ),
                ),
                // 作为 RecyclerView 的兄弟节点悬浮覆盖在其上方
                ScreenNodeDescriptor(
                    role = "ImageButton",
                    contentDescription = "新建笔记",
                    resourceId = "com.notes:id/fab_add",
                    bounds = ScreenBounds(860, 2040, 1020, 2200),
                    clickable = true,
                ),
            ),
        )
        val sig = ScreenSignatureExtractor.extract(tree, packageName = "com.notes", activityName = ".MainActivity", screenWidth = 1080, screenHeight = 2400)
        assertTrue("笔记" in sig.anchors)
        assertTrue("新建笔记" in sig.anchors)
        assertTrue("fab_add" in sig.resourceIds)
        assertFalse("机密会议纪要" in sig.anchors)
    }

    @Test
    fun testMultipleSingleActivityComposePagesDoNotMatch() {
        val home = ScreenSignatureExtractor.extract(
            root = ScreenNodeDescriptor(
                role = "View",
                bounds = ScreenBounds(0, 0, 1080, 2400),
                children = listOf(
                    ScreenNodeDescriptor(role = "TextView", text = "首页", bounds = ScreenBounds(40, 80, 200, 150)),
                    ScreenNodeDescriptor(role = "Button", text = "搜索", bounds = ScreenBounds(880, 80, 1040, 150), clickable = true),
                    ScreenNodeDescriptor(role = "View", scrollable = true, bounds = ScreenBounds(0, 180, 1080, 2180)),
                    ScreenNodeDescriptor(role = "Button", text = "首页", bounds = ScreenBounds(0, 2180, 360, 2380), clickable = true, selected = true),
                    ScreenNodeDescriptor(role = "Button", text = "分类", bounds = ScreenBounds(360, 2180, 720, 2380), clickable = true),
                    ScreenNodeDescriptor(role = "Button", text = "我的", bounds = ScreenBounds(720, 2180, 1080, 2380), clickable = true),
                ),
            ),
            packageName = "com.compose.app",
            activityName = "com.compose.app/.MainActivity",
            screenWidth = 1080,
            screenHeight = 2400,
        )

        val settings = ScreenSignatureExtractor.extract(
            root = ScreenNodeDescriptor(
                role = "View",
                bounds = ScreenBounds(0, 0, 1080, 2400),
                children = listOf(
                    ScreenNodeDescriptor(role = "ImageButton", contentDescription = "返回", bounds = ScreenBounds(20, 80, 120, 150), clickable = true),
                    ScreenNodeDescriptor(role = "TextView", text = "设置", bounds = ScreenBounds(140, 80, 300, 150)),
                    ScreenNodeDescriptor(role = "TextView", text = "账号与安全", bounds = ScreenBounds(40, 240, 400, 320), clickable = true),
                    ScreenNodeDescriptor(role = "TextView", text = "通知提醒", bounds = ScreenBounds(40, 380, 400, 460), clickable = true),
                    ScreenNodeDescriptor(role = "TextView", text = "隐私管理", bounds = ScreenBounds(40, 520, 400, 600), clickable = true),
                    ScreenNodeDescriptor(role = "Button", text = "退出登录", bounds = ScreenBounds(80, 1900, 1000, 2020), clickable = true),
                ),
            ),
            packageName = "com.compose.app",
            activityName = "com.compose.app/.MainActivity",
            screenWidth = 1080,
            screenHeight = 2400,
        )

        val detail = ScreenSignatureExtractor.extract(
            root = ScreenNodeDescriptor(
                role = "View",
                bounds = ScreenBounds(0, 0, 1080, 2400),
                children = listOf(
                    ScreenNodeDescriptor(role = "ImageButton", contentDescription = "返回", bounds = ScreenBounds(20, 80, 120, 150), clickable = true),
                    ScreenNodeDescriptor(role = "TextView", text = "商品详情", bounds = ScreenBounds(140, 80, 400, 150)),
                    ScreenNodeDescriptor(role = "ImageButton", contentDescription = "分享", bounds = ScreenBounds(940, 80, 1040, 150), clickable = true),
                    ScreenNodeDescriptor(role = "Button", text = "加入购物车", bounds = ScreenBounds(320, 2180, 680, 2340), clickable = true),
                    ScreenNodeDescriptor(role = "Button", text = "立即购买", bounds = ScreenBounds(700, 2180, 1040, 2340), clickable = true),
                ),
            ),
            packageName = "com.compose.app",
            activityName = "com.compose.app/.MainActivity",
            screenWidth = 1080,
            screenHeight = 2400,
        )

        assertFalse(home.matches(settings))
        assertFalse(home.matches(detail))
        assertFalse(settings.matches(detail))
    }

    @Test
    fun testHammingHelpersAndSameSignatureIdentity() {
        val h1 = -0x123456789abcdef0L
        val h2 = h1 xor 0b10101L // 3 bits differ
        assertEquals(3, ScreenSignature.hammingDistance(h1, h2))
        assertEquals(1.0 - 3.0 / 64.0, ScreenSignature.simHashSimilarity(h1, h2), 1e-6)

        val s1 = ScreenSignature(fingerprint = h1, sigId = "Main#1", packageName = "com.x", activity = "com.x/.Main", staticNodeCount = 5)
        val s2 = ScreenSignature(fingerprint = h2, sigId = "Main#2", packageName = "com.x", activity = "com.x/.Main", staticNodeCount = 5)
        assertTrue(s1.matches(s2))
    }

    @Test
    fun testDifferentPackageOrActivityNeverMatches() {
        val tree = ScreenNodeDescriptor(
            role = "LinearLayout",
            bounds = ScreenBounds(0, 0, 1080, 2400),
            children = listOf(
                ScreenNodeDescriptor(role = "TextView", text = "设置", bounds = ScreenBounds(40, 80, 240, 150)),
                ScreenNodeDescriptor(role = "Button", text = "退出登录", bounds = ScreenBounds(80, 1800, 1000, 1920), clickable = true),
            ),
        )
        val sigA = ScreenSignatureExtractor.extract(tree, packageName = "com.app.a", activityName = ".SettingsActivity", screenWidth = 1080, screenHeight = 2400)
        val sigB = ScreenSignatureExtractor.extract(tree, packageName = "com.app.b", activityName = ".SettingsActivity", screenWidth = 1080, screenHeight = 2400)
        val sigC = ScreenSignatureExtractor.extract(tree, packageName = "com.app.a", activityName = ".OtherActivity", screenWidth = 1080, screenHeight = 2400)

        assertEquals(0.0, sigA.similarity(sigB), 0.0)
        assertFalse(sigA.matches(sigB))
        assertEquals(0.0, sigA.similarity(sigC), 0.0)
        assertFalse(sigA.matches(sigC))
    }

    @Test
    fun testBlankAndNoWindowHandling() {
        val emptyNodesSig = ScreenSignatureExtractor.extract(emptyList(), packageName = "com.example", activityName = ".SplashActivity")
        val layoutOnlySig = ScreenSignatureExtractor.extract(
            root = ScreenNodeDescriptor(
                role = "FrameLayout",
                children = listOf(ScreenNodeDescriptor(role = "LinearLayout", visible = true)),
            ),
            packageName = "com.example",
            activityName = ".SplashActivity",
        )
        val invisibleOnlySig = ScreenSignatureExtractor.extract(
            root = ScreenNodeDescriptor(role = "TextView", text = "隐藏文字", visible = false),
        )

        assertTrue(ScreenSignature.EMPTY.isBlank)
        assertTrue(emptyNodesSig.isBlank)
        assertTrue(layoutOnlySig.isBlank)
        assertTrue(invisibleOnlySig.isBlank)

        assertEquals(0L, ScreenSignature.EMPTY.fingerprint)
        assertEquals(0.0, ScreenSignature.EMPTY.similarity(ScreenSignature.EMPTY), 0.0)
        assertFalse(ScreenSignature.EMPTY.matches(ScreenSignature.EMPTY))
        assertFalse(emptyNodesSig.matches(layoutOnlySig))

        val inspector = DisplayWindowInspector(serviceProvider = { null })
        val bridge = AgentA11yBridge(windowInspector = inspector)
        assertEquals(ScreenSignature.EMPTY, inspector.screenSignature(0))
        assertEquals(ScreenSignature.EMPTY, bridge.screenSignature(0))
        assertEquals(ScreenSignature.EMPTY, DisplayWindowInspector.screenSignature(emptyList()))
    }

    @Test
    fun testA11yNodeExtraction() {
        val node = A11yNode(
            className = "android.widget.LinearLayout",
            packageName = "com.example.shop",
            children = listOf(
                A11yNode(text = "购物车(2)", viewId = "com.example.shop:id/cart_title", className = "android.widget.TextView"),
                A11yNode(text = "结算", viewId = "com.example.shop:id/btn_checkout", className = "android.widget.Button", isClickable = true),
                A11yNode(text = "secret", hintText = "口令", className = "android.widget.EditText", isEditable = true, isPassword = true),
            ),
        )
        val sig = DisplayWindowInspector.screenSignatureFromNodes(
            roots = listOf(node),
            activityName = "com.example.shop/.CartActivity",
        )
        assertFalse(sig.isBlank)
        assertEquals("com.example.shop", sig.packageName)
        assertEquals("CartActivity", sig.shortActivity)
        assertTrue("购物车" in sig.anchors)
        assertTrue("结算" in sig.anchors)
        assertTrue("口令" in sig.anchors)
        assertFalse("secret" in sig.anchors)
        assertEquals(listOf("btn_checkout", "cart_title"), sig.resourceIds)
        assertNotEquals(0L, sig.fingerprint)
    }

    private fun buildWeChatTab(
        title: String,
        selectedIndex: Int,
        bottomBadgeFirstTab: String = "微信",
        listResourceId: String,
        listItems: List<Pair<String, String>>,
        unreadBadgeOverlay: String? = null,
        extraTopAction: Pair<String, String>? = null,
        extraHeaderButton: Pair<String, String>? = null,
    ): ScreenNodeDescriptor {
        val tabNames = listOf(bottomBadgeFirstTab, "通讯录", "发现", "我")
        val tabIds = listOf("tab_chats", "tab_contacts", "tab_discover", "tab_me")
        val bottomTabs = tabNames.mapIndexed { idx, name ->
            ScreenNodeDescriptor(
                role = "LinearLayout",
                resourceId = "com.tencent.mm:id/${tabIds[idx]}",
                bounds = ScreenBounds(idx * 270, 2180, (idx + 1) * 270, 2380),
                clickable = true,
                selected = idx == selectedIndex,
                children = listOfNotNull(
                    ScreenNodeDescriptor(
                        role = "TextView",
                        text = name,
                        bounds = ScreenBounds(idx * 270 + 40, 2290, (idx + 1) * 270 - 40, 2350),
                    ),
                    if (idx == 0 && unreadBadgeOverlay != null) {
                        ScreenNodeDescriptor(
                            role = "TextView",
                            text = unreadBadgeOverlay,
                            bounds = ScreenBounds(180, 2190, 240, 2230),
                        )
                    } else null,
                ),
            )
        }

        val topChildren = mutableListOf(
            ScreenNodeDescriptor(role = "TextView", text = title, bounds = ScreenBounds(40, 80, 320, 150)),
            ScreenNodeDescriptor(role = "ImageButton", contentDescription = "搜索", resourceId = "com.tencent.mm:id/search_btn", bounds = ScreenBounds(820, 75, 920, 155), clickable = true),
            ScreenNodeDescriptor(role = "ImageButton", contentDescription = "+", resourceId = "com.tencent.mm:id/plus_btn", bounds = ScreenBounds(940, 75, 1040, 155), clickable = true),
        )
        if (extraTopAction != null) {
            topChildren += ScreenNodeDescriptor(
                role = "ImageButton",
                contentDescription = extraTopAction.first,
                resourceId = extraTopAction.second,
                bounds = ScreenBounds(700, 75, 800, 155),
                clickable = true,
            )
        }

        val listChildren = listItems.mapIndexed { idx, (name, preview) ->
            ScreenNodeDescriptor(
                role = "LinearLayout",
                bounds = ScreenBounds(0, 200 + idx * 180, 1080, 380 + idx * 180),
                clickable = true,
                children = listOf(
                    ScreenNodeDescriptor(role = "TextView", text = name, bounds = ScreenBounds(160, 220 + idx * 180, 500, 270 + idx * 180)),
                    ScreenNodeDescriptor(role = "TextView", text = preview, bounds = ScreenBounds(160, 280 + idx * 180, 960, 340 + idx * 180)),
                ),
            )
        }

        val bodyChildren = mutableListOf<ScreenNodeDescriptor>()
        if (extraHeaderButton != null) {
            bodyChildren += ScreenNodeDescriptor(
                role = "Button",
                text = extraHeaderButton.first,
                resourceId = extraHeaderButton.second,
                bounds = ScreenBounds(220, 380, 380, 450),
                clickable = true,
            )
        }
        bodyChildren += ScreenNodeDescriptor(
            role = "RecyclerView",
            resourceId = listResourceId,
            bounds = ScreenBounds(0, 180, 1080, 2170),
            scrollable = true,
            children = listChildren,
        )

        return ScreenNodeDescriptor(
            role = "FrameLayout",
            bounds = ScreenBounds(0, 0, 1080, 2400),
            children = topChildren + bodyChildren + bottomTabs,
        )
    }
}
