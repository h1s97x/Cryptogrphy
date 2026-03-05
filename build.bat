@echo off
chcp 65001 >nul
echo ========================================
echo 密码学平台 - 应用打包工具
echo ========================================
echo.

echo [1/4] 清理旧的构建文件...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
echo 完成！
echo.

echo [2/4] 开始打包应用...
pyinstaller build_config.spec --clean
echo 完成！
echo.

echo [3/4] 检查打包结果...
if exist "dist\密码学平台\密码学平台.exe" (
    echo ✓ 打包成功！
    echo.
    echo 可执行文件位置: dist\密码学平台\密码学平台.exe
) else (
    echo ✗ 打包失败，请检查错误信息
    pause
    exit /b 1
)
echo.

echo [4/4] 创建发布包...
cd dist
if exist "密码学平台.zip" del "密码学平台.zip"
powershell -command "Compress-Archive -Path '密码学平台' -DestinationPath '密码学平台.zip'"
cd ..
echo 完成！
echo.

echo ========================================
echo 打包完成！
echo ========================================
echo.
echo 发布文件:
echo   - 文件夹: dist\密码学平台\
echo   - 压缩包: dist\密码学平台.zip
echo.
echo 可以将整个文件夹或压缩包分享给其他人使用
echo.
pause
