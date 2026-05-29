@echo off
echo === Nixiang MCP Setup ===
echo.

REM 创建虚拟环境
if not exist venv (
    echo [1/3] Creating virtual environment...
    python -m venv venv
) else (
    echo [1/3] Virtual environment already exists, skipping.
)

REM 安装依赖
echo [2/3] Installing dependencies...
venv\Scripts\pip install -r requirements.txt -q

REM 下载 dnlib.dll
if not exist dnlib.dll (
    echo [3/3] Downloading dnlib.dll...
    curl -L -o dnlib.nupkg "https://www.nuget.org/api/v2/package/dnlib"
    tar -xf dnlib.nupkg -d dnlib-temp >nul 2>&1
    copy dnlib-temp\lib\net45\dnlib.dll . >nul
    rmdir /s /q dnlib-temp
    del dnlib.nupkg
) else (
    echo [3/3] dnlib.dll already exists, skipping.
)

echo.
echo === Setup Complete ===
echo Run 'claude' to start.
pause