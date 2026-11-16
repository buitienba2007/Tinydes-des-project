@echo off
rem ================================================================
rem build.bat - Bien dich TinyDES + DES thanh thu vien dong cipher.dll
rem             de Python goi qua ctypes.
rem
rem Cach chay: nhay dup vao file nay, hoac mo Command Prompt va go: build
rem Ket qua : core\cipher.dll
rem
rem Luu y   : Python 64-bit can DLL 64-bit (dung gcc / cl ban 64-bit).
rem ================================================================

rem Chuyen ve thu muc chua file build.bat (thu muc core)
cd /d "%~dp0"

set SOURCES=tinydes.c des.c
set OUTPUT=cipher.dll

rem ---------- Cach 1: MinGW gcc ----------
where gcc >nul 2>nul
if %errorlevel%==0 (
    echo [build] Dung MinGW gcc
    gcc -std=c99 -O2 -Wall -Wextra -shared -static-libgcc -o %OUTPUT% %SOURCES%
    goto check
)

rem ---------- Cach 2: MSVC (mo "Developer Command Prompt for VS") ----------
where cl >nul 2>nul
if %errorlevel%==0 (
    echo [build] Dung MSVC cl
    cl /nologo /O2 /W3 /utf-8 /D_CRT_SECURE_NO_WARNINGS /LD %SOURCES% /Fe:%OUTPUT%
    del /q *.obj *.exp *.lib 2>nul
    goto check
)

echo [build] LOI: khong tim thay gcc hoac cl.
echo         Cai MinGW-w64 va them thu muc bin vao PATH,
echo         hoac mo "Developer Command Prompt for VS" roi chay lai.
pause
exit /b 1

:check
if exist %OUTPUT% (
    echo [build] Thanh cong: %~dp0%OUTPUT%
) else (
    echo [build] Bien dich that bai, xem loi o tren.
    pause
    exit /b 1
)
pause
