# 贡献指南 (Contributing Guide)

感谢您对 Android Agent Use (AAU) 项目的关注与贡献！我们欢迎各种形式的贡献，包括代码、文档、ROM 兼容性适配测试及 issue 反馈。

---

## 1. 行为规范

参与本项目的所有成员均需遵守友好、互相尊重、包容互助的开源社区准则。

## 2. 开发与分支模型

- `main` 分支为主干分支，保持生产稳定状态；
- 开发新特性或修复 Bug 时，请从 `main` 分支检出功能分支，命名规范：
  - `feat/feature-name`
  - `fix/bug-description`
  - `docs/doc-updates`
  - `refactor/clean-up`

## 3. 本地构建与测试流程

AAU 为标准 Gradle 多模块工程，包含 `aau-common`, `aau-server`, `aau-client`, `aau-a11y`, `aau-setup` 等模块：

1. **环境依赖**：
   - JDK 17
   - Android SDK 35+ (compileSdk 36)
2. **构建验证**：
   ```bash
   ./gradlew clean assembleDebug
   ```
3. **打包独立服务端**：
   ```bash
   ./gradlew packageServerDex
   ```
4. **运行全量测试**：
   ```bash
   ./gradlew testDebugUnitTest
   ```

提交 Pull Request 前，请确保所有单元测试 100% 通过。

## 4. 代码风格规范

- **Kotlin 优先**：所有新功能模块强制使用 Kotlin 编写；
- **架构解耦**：
  - 核心契约与数据模型定义在 `aau-common` 中，保持 0 业务污染；
  - 服务端逻辑（Shell UID 2000）与客户端 SDK 保持清晰边界，不得发生反向或循环依赖；
  - 严格保持向后兼容性与对 Android 12~15 各大 OEM 定制系统的降级容错。
- **格式化**：遵循 `.editorconfig` 规范，提交前清理无用导入与尾部空格。

## 5. Pull Request 提交要求

1. 提交信息（Git Commit Message）遵循约定式提交规范：
   - `feat(client): add dynamic frame throttling queue`
   - `fix(server): resolve AppOps restore mode dirty state`
   - `docs(readme): add comparison matrix against scrcpy`
2. PR 描述中清晰说明修改背景、解决的问题、影响的模块及测试结果；
3. 新增特权操作或底层反射调用时，必须附带安全影响评估与降级机制说明。
