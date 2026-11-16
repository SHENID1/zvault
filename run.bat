@echo off
title ZCode Secret Masking Proxy
cd /d "%~dp0"
echo Starting ZCode Secret Masking Proxy on http://127.0.0.1:8765...
python server.py
pause
