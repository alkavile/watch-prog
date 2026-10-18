#include "app.h"
#include "agent.h"
#include "launcher.h"
#include "ui.h"
#include "util.h"

#include <commctrl.h>
#include <shellapi.h>
#include <objbase.h>
#include <string>

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR commandLine, int showCommand) {
    (void)previous;
    (void)commandLine;
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        if (argc >= 5 && _wcsicmp(argv[1], L"--agent") == 0) {
            std::wstring commandPipe = argv[2];
            std::wstring eventPipe = argv[3];
            std::wstring secret = argv[4];
            LocalFree(argv);
            int result = AgentMain(commandPipe, eventPipe, secret);
            CoUninitialize();
            return result;
        }
        if (argc >= 3 && _wcsicmp(argv[1], L"--load-dll") == 0) {
            std::wstring path = argv[2];
            LocalFree(argv);
            int exitCode = 0;
            Launcher_LoadDllHelper(path, exitCode);
            CoUninitialize();
            return exitCode;
        }
    }

    std::wstring initialFile;
    if (argv && argc >= 2 && argv[1][0] != L'-') {
        initialFile = argv[1];
    }
    if (argv) LocalFree(argv);

    INITCOMMONCONTROLSEX controls = {};
    controls.dwSize = sizeof(controls);
    controls.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&controls);

    int result = RunGui(instance, showCommand, initialFile);
    CoUninitialize();
    return result;
}
