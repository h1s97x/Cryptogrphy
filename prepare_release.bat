@echo off
chcp 65001 >nul
echo ========================================
echo 密码学平台 - Release 准备工具
echo ========================================
echo.

set VERSION=v2.2.0

echo 当前版本: %VERSION%
echo.

echo [步骤 1/5] 检查 Git 状态...
git status
echo.

echo [步骤 2/5] 推送代码到 GitHub...
echo 推送到 main 分支...
git push origin main
if errorlevel 1 (
    echo ✗ 推送失败，请检查网络连接
    pause
    exit /b 1
)
echo ✓ 推送成功
echo.

echo [步骤 3/5] 创建 Git 标签...
git tag -a %VERSION% -m "Release %VERSION% - 完整功能版本"
if errorlevel 1 (
    echo ✗ 标签创建失败（可能已存在）
    echo 如需重新创建，请先删除旧标签: git tag -d %VERSION%
    pause
    exit /b 1
)
echo ✓ 标签创建成功
echo.

echo [步骤 4/5] 推送标签到 GitHub...
git push origin %VERSION%
if errorlevel 1 (
    echo ✗ 标签推送失败
    pause
    exit /b 1
)
echo ✓ 标签推送成功
echo.

echo [步骤 5/5] 打包应用...
echo 开始打包，这可能需要几分钟...
call build.bat
if errorlevel 1 (
    echo ✗ 打包失败
    pause
    exit /b 1
)
echo.

echo ========================================
echo Release 准备完成！
echo ========================================
echo.
echo 版本: %VERSION%
echo 标签已推送到 GitHub
echo.
echo 📦 发布文件:
echo   - dist\密码学平台.zip
echo.
echo 🌐 下一步操作:
echo 1. 访问 GitHub Releases 页面
echo    https://github.com/h1s97x/PyCryptoLab/releases
echo.
echo 2. 点击 "Draft a new release"
echo.
echo 3. 选择标签: %VERSION%
echo.
echo 4. 填写 Release 信息（参考 RELEASE_NOTES.md）
echo.
echo 5. 上传文件: dist\密码学平台.zip
echo.
echo 6. 点击 "Publish release"
echo.
pause
