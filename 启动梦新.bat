@echo off
chcp 65001 >nul
cd /d "%~dp0"
title MengXin AI
echo ==================================
echo   MengXin AI - Chat
echo   Type your question. Say "exit" to quit.
echo ==================================
echo.
python -X utf8 chat.py
if errorlevel 1 (
  echo [ERROR] Python not found or startup failed.
  pause
)
pause
