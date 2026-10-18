#ifndef WATCHPROG_APP_H
#define WATCHPROG_APP_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <cstdint>

#define WATCHPROG_NAME          L"WatchProg"
#define WATCHPROG_VERSION       L"v1.01-beta.04"
#define WATCHPROG_VERSION_FULL  L"WatchProg v1.01-beta.04"
#define WATCHPROG_AUTHOR        L"AlkaVile"
#define WATCHPROG_WINDOW_W      1200
#define WATCHPROG_WINDOW_H      900
#define WATCHPROG_PROTOCOL      2
#define WATCHPROG_FONT_RESOURCE_ID 102

// Menu commands
enum : UINT {
    IDM_FILE_OPEN = 1001,
    IDM_FILE_RERUN,
    IDM_FILE_STOP,
    IDM_FILE_CLEAR,
    IDM_FILE_EXPORT,
    IDM_FILE_EXIT,
    IDM_VIEW_FILES = 1101,
    IDM_VIEW_REGISTRY,
    IDM_VIEW_TASKS,
    IDM_VIEW_PROCESSES,
    IDM_VIEW_NETWORK,
    IDM_VIEW_AUTOSCROLL,
    IDM_HELP_HOW,
    IDM_HELP_ABOUT,
    IDC_LIST = 2001,
    IDC_OPEN_BUTTON,
    IDC_STOP_BUTTON,
    IDC_RERUN_BUTTON,
    IDC_STATUS = 2010,
    IDC_EMPTY_HINT = 2011,
    IDC_VERSION_LABEL = 2012,
    IDC_FOOTER_STATUS = 2013,
    IDC_FOOTER_COUNTS = 2014
};

// WM_APP messages are unused: the UI drains agent events on a timer.
#define WATCHPROG_TIMER_UI      1
#define WATCHPROG_TIMER_STATUS  2

enum EventCategory : int {
    CatFile = 0,
    CatRegistry = 1,
    CatTasks = 2,
    CatProcess = 3,
    CatNetwork = 4,
    CatSystem = 5,
    CatCount = 6
};

struct LogEvent {
    FILETIME time{};
    int category = CatSystem;
    std::wstring action;
    std::wstring object;
    std::wstring details;
    bool underline = false;
};

struct EventFilter {
    bool enabled[CatCount] = { true, true, true, true, true, true };
    bool Matches(int category) const {
        return category >= 0 && category < CatCount && enabled[category];
    }
    bool AllEnabled() const {
        for (int i = 0; i < CatCount; ++i) if (!enabled[i]) return false;
        return true;
    }
};

const wchar_t* CategoryName(int category);

#endif
