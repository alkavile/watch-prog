#include "launcher.h"
#include "util.h"

#include <shellapi.h>
#include <string>
#include <vector>

namespace {

std::wstring SystemFile(const wchar_t* relative) {
    wchar_t systemDir[MAX_PATH] = {};
    GetSystemDirectoryW(systemDir, MAX_PATH);
    return JoinPath(systemDir, relative);
}

std::wstring PowerShellPath() {
    wchar_t systemDir[MAX_PATH] = {};
    GetSystemDirectoryW(systemDir, MAX_PATH);
    std::wstring path = JoinPath(systemDir, L"WindowsPowerShell\\v1.0\\powershell.exe");
    if (FileExists(path)) return path;
    return L"powershell.exe";
}

std::wstring CmdPath() {
    wchar_t value[32768] = {};
    DWORD len = GetEnvironmentVariableW(L"ComSpec", value, 32768);
    if (len > 0 && len < 32768) return value;
    return SystemFile(L"cmd.exe");
}

std::wstring QuotePowerShellSingle(const std::wstring& text) {
    std::wstring result;
    result.reserve(text.size() + 4);
    for (wchar_t c : text) {
        if (c == L'\'') result += L"''";
        else result += c;
    }
    return result;
}

bool CreateSuspended(const std::wstring& application, const std::wstring& commandLine,
                     const std::wstring& workDir, DWORD flags, PreparedTarget& target,
                     std::wstring& error) {
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = (flags & CREATE_NO_WINDOW) ? SW_HIDE : SW_SHOWNORMAL;
    PROCESS_INFORMATION process = {};
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');
    BOOL ok = CreateProcessW(
        application.empty() ? nullptr : application.c_str(),
        mutableCommand.data(),
        nullptr, nullptr, FALSE,
        flags | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
        nullptr,
        workDir.empty() ? nullptr : workDir.c_str(),
        &startup, &process);
    if (!ok) {
        error = L"Не удалось создать процесс: " + FormatWinError(GetLastError());
        return false;
    }
    target.process = process.hProcess;
    target.thread = process.hThread;
    target.pid = process.dwProcessId;
    target.command = commandLine;
    target.application = application;
    return true;
}

} // namespace

bool Launcher_Prepare(const std::wstring& path, const std::wstring& extension,
                      PreparedTarget& target, std::wstring& error) {
    target = {};
    std::wstring ext = ToLower(extension);
    if (ext == L".ms\u0441") ext = L".msc";
    std::wstring workDir = DirectoryOf(path);
    std::wstring application;
    std::wstring commandLine;
    DWORD flags = CREATE_UNICODE_ENVIRONMENT;

    if (ext == L".exe" || ext == L".com" || ext == L".scr") {
        application = path;
        commandLine = QuoteArg(path);
    } else if (ext == L".bat" || ext == L".cmd") {
        application = CmdPath();
        commandLine = QuoteArg(application) + L" /D /S /C call " + QuoteArg(path);
    } else if (ext == L".vbs" || ext == L".vbe") {
        application = SystemFile(L"wscript.exe");
        commandLine = QuoteArg(application) + L" //nologo " + QuoteArg(path);
    } else if (ext == L".ps1") {
        application = PowerShellPath();
        commandLine = QuoteArg(application) +
                      L" -NoLogo -NoProfile -ExecutionPolicy Bypass -File " + QuoteArg(path);
    } else if (ext == L".msi") {
        application = SystemFile(L"msiexec.exe");
        commandLine = QuoteArg(application) + L" /i " + QuoteArg(path);
    } else if (ext == L".cpl") {
        application = SystemFile(L"control.exe");
        commandLine = QuoteArg(application) + L" " + QuoteArg(path);
    } else if (ext == L".msc") {
        application = SystemFile(L"mmc.exe");
        commandLine = QuoteArg(application) + L" " + QuoteArg(path);
    } else if (ext == L".dll") {
        application = GetExePath();
        commandLine = QuoteArg(application) + L" --load-dll " + QuoteArg(path);
        flags |= CREATE_NO_WINDOW;
    } else if (ext == L".appx" || ext == L".msix" || ext == L".msixbundle" || ext == L".appxbundle") {
        application = PowerShellPath();
        commandLine = QuoteArg(application) +
                      L" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " +
                      QuoteArg(L"Add-AppxPackage -Path '" + QuotePowerShellSingle(path) + L"'");
        flags |= CREATE_NO_WINDOW;
    } else if (ext == L".appinstaller") {
        application = PowerShellPath();
        commandLine = QuoteArg(application) +
                      L" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " +
                      QuoteArg(L"Add-AppxPackage -AppInstallerFile '" + QuotePowerShellSingle(path) + L"'");
        flags |= CREATE_NO_WINDOW;
    } else {
        error = L"Этот тип файла не поддерживается для запуска.";
        return false;
    }

    if (!FileExists(application)) {
        error = L"Не найден исполняемый файл: " + application;
        return false;
    }
    return CreateSuspended(application, commandLine, workDir, flags, target, error);
}

bool Launcher_Resume(PreparedTarget& target, std::wstring& error) {
    if (!target.thread) {
        error = L"Процесс не был подготовлен.";
        return false;
    }
    if (ResumeThread(target.thread) == static_cast<DWORD>(-1)) {
        error = L"Не удалось запустить процесс: " + FormatWinError(GetLastError());
        Launcher_Abort(target);
        return false;
    }
    return true;
}

void Launcher_Abort(PreparedTarget& target) {
    if (target.process) TerminateProcess(target.process, 1);
    Launcher_Close(target);
}

void Launcher_Close(PreparedTarget& target) {
    if (target.thread) {
        CloseHandle(target.thread);
        target.thread = nullptr;
    }
    if (target.process) {
        CloseHandle(target.process);
        target.process = nullptr;
    }
    target.pid = 0;
}

bool Launcher_LoadDllHelper(const std::wstring& path, int& exitCode) {
    HMODULE module = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!module) {
        exitCode = static_cast<int>(GetLastError());
        return false;
    }
    // Give the library a chance to execute work started from DllMain and worker threads.
    Sleep(7000);
    FreeLibrary(module);
    exitCode = 0;
    return true;
}
