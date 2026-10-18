#ifndef WATCHPROG_THEME_H
#define WATCHPROG_THEME_H

#include "app.h"

enum class ThemeKind {
    Light,
    Dark,
    HighContrast
};

struct Theme {
    ThemeKind kind = ThemeKind::Light;
    bool dark = false;
    int dpi = 96;
    COLORREF windowBg = RGB(242, 244, 248);
    COLORREF panelBg = RGB(255, 255, 255);
    COLORREF listBg = RGB(255, 255, 255);
    COLORREF text = RGB(24, 28, 34);
    COLORREF muted = RGB(92, 102, 114);
    COLORREF border = RGB(198, 206, 216);
    COLORREF accent = RGB(0, 95, 184);
    COLORREF selectionBg = RGB(0, 120, 215);
    COLORREF selectionText = RGB(255, 255, 255);
    COLORREF category[CatCount] = {};
    HFONT fontUi = nullptr;
    HFONT fontUiBold = nullptr;
    HFONT fontUiUnderline = nullptr;
    HFONT fontTitle = nullptr;
    HFONT fontSmall = nullptr;
    HFONT fontMono = nullptr;
    HBRUSH windowBrush = nullptr;
    HBRUSH panelBrush = nullptr;
    int Scale(int value) const { return MulDiv(value, dpi, 96); }
};

extern Theme g_theme;

void Theme_Initialize(HWND hwnd);
void Theme_Refresh(HWND hwnd);
void Theme_Shutdown();
void Theme_ApplyWindow(HWND hwnd);
void Theme_ApplyControls(HWND root);
int Theme_CurrentDpi(HWND hwnd);
const std::wstring& Theme_UiFontFamily();

#endif
