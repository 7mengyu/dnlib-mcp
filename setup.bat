@echo off
echo === Nixiang MCP Setup ===
echo.

REM 创建虚拟环境
if not exist venv (
    echo [1/2] Creating virtual environment...
    python -m venv venv
) else (
    echo [1/2] Virtual environment already exists, skipping.
)

REM 安装依赖
echo [2/2] Installing dependencies...
venv\Scripts\pip install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/ -q

echo.
echo === Setup Complete ===
echo Run 'claude' to start.
pause