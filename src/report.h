#ifndef WATCHPROG_REPORT_H
#define WATCHPROG_REPORT_H

#include "app.h"

bool Report_Save(HWND owner, const std::vector<LogEvent>& events, const std::wstring& targetPath);

#endif
