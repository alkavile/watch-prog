@echo off
setlocal
cd /d "%~dp0"

set "PATH=C:\msys64\ucrt64\bin;%PATH%"
where g++ >nul 2>nul
if errorlevel 1 (
  echo GCC not found. Install MSYS2 UCRT64 or add C:\msys64\ucrt64\bin to PATH.
  exit /b 1
)
where windres >nul 2>nul
if errorlevel 1 (
  echo windres not found. Install MSYS2 binutils.
  exit /b 1
)

if not exist build mkdir build

echo [1/3] Resources
windres -I res -i res\watchprog.rc -o build\watchprog.o --codepage=65001
if errorlevel 1 goto :failed

echo [2/3] Compile and link
g++ -std=c++17 -O2 -s -municode -mwindows ^
  -DUNICODE -D_UNICODE -DWINVER=0x0A00 -D_WIN32_WINNT=0x0A00 ^
  -finput-charset=UTF-8 -fexec-charset=UTF-8 -fwide-exec-charset=UTF-16LE ^
  -ffunction-sections -fdata-sections -Wl,--gc-sections ^
  src\main.cpp src\ui.cpp src\theme.cpp src\util.cpp src\report.cpp ^
  src\launcher.cpp src\etw.cpp src\monitor.cpp src\agent.cpp src\agent_client.cpp ^
  build\watchprog.o ^
  -o WatchProg.exe ^
  -static -static-libgcc -static-libstdc++ ^
  -lcomctl32 -lcomdlg32 -lshell32 -lole32 -loleaut32 -luuid ^
  -ladvapi32 -ltdh -ldwmapi -luxtheme -lws2_32 -liphlpapi ^
  -lgdi32 -luser32 -lkernel32
if errorlevel 1 goto :failed

echo [3/3] Done
echo Built: %~dp0WatchProg.exe
exit /b 0

:failed
echo.
echo BUILD FAILED
exit /b 1