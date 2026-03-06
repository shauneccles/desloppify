@echo off
set DESLOPPIFY_PARALLEL=1
uv run python -m desloppify scan --path .. >NUL 2>&1
exit /b %ERRORLEVEL%
