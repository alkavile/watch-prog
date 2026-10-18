#ifndef WATCHPROG_LAUNCHER_H
#define WATCHPROG_LAUNCHER_H

#include "app.h"

struct PreparedTarget {
    HANDLE process = nullptr;
    HANDLE thread = nullptr;
    DWORD pid = 0;
    std::wstring command;
    std::wstring application;
};

bool Launcher_Prepare(const std::wstring& path, const std::wstring& extension,
                      PreparedTarget& target, std::wstring& error);
bool Launcher_Resume(PreparedTarget& target, std::wstring& error);
void Launcher_Abort(PreparedTarget& target);
void Launcher_Close(PreparedTarget& target);
bool Launcher_LoadDllHelper(const std::wstring& path, int& exitCode);

#endif
