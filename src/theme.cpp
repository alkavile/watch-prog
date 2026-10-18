#include "theme.h"
#include "util.h"

#include <dwmapi.h>
#include <uxtheme.h>
#include <algorithm>
#include <cstring>

Theme g_theme;

namespace {

HANDLE g_memFontHandle = nullptr;
std::wstring g_uiFontFamily = L"Segoe UI";
bool g_fontResourceAttempted = false;

uint16_t ReadBigEndian16(const BYTE* data) {
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
}

uint32_t ReadBigEndian32(const BYTE* data) {
    return (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) | data[3];
}

std::wstring DecodeFontName(const BYTE* data, size_t length, bool utf16) {
    std::wstring result;
    if (utf16) {
        result.reserve(length / 2);
        for (size_t i = 0; i + 1 < length; i += 2) {
            uint16_t unit = ReadBigEndian16(data + i);
            result.push_back(static_cast<wchar_t>(unit));
        }
    } else {
        result.reserve(length);
        for (size_t i = 0; i < length; ++i) {
            if (data[i] == 0) break;
            result.push_back(static_cast<wchar_t>(data[i]));
        }
    }
    size_t nullPos = result.find(L'\0');
    if (nullPos != std::wstring::npos) result.resize(nullPos);
    return result;
}

std::wstring ReadFamilyFromFont(const BYTE* data, size_t size) {
    if (!data || size < 12) return L"";
    uint16_t tableCount = ReadBigEndian16(data + 4);
    const BYTE* nameTable = nullptr;
    size_t nameSize = 0;
    for (uint16_t i = 0; i < tableCount; ++i) {
        size_t record = 12 + static_cast<size_t>(i) * 16;
        if (record + 16 > size) break;
        if (std::memcmp(data + record, "name", 4) == 0) {
            uint32_t offset = ReadBigEndian32(data + record + 8);
            uint32_t length = ReadBigEndian32(data + record + 12);
            if (offset <= size && length <= size - offset) {
                nameTable = data + offset;
                nameSize = length;
            }
            break;
        }
    }
    if (!nameTable || nameSize < 6) return L"";
    uint16_t count = ReadBigEndian16(nameTable + 2);
    uint16_t stringOffset = ReadBigEndian16(nameTable + 4);
    if (stringOffset > nameSize) return L"";
    std::wstring family;
    int bestScore = -1;
    for (uint16_t i = 0; i < count; ++i) {
        size_t record = 6 + static_cast<size_t>(i) * 12;
        if (record + 12 > nameSize) break;
        uint16_t platform = ReadBigEndian16(nameTable + record);
        uint16_t encoding = ReadBigEndian16(nameTable + record + 2);
        uint16_t language = ReadBigEndian16(nameTable + record + 4);
        uint16_t nameId = ReadBigEndian16(nameTable + record + 6);
        uint16_t length = ReadBigEndian16(nameTable + record + 8);
        uint16_t offset = ReadBigEndian16(nameTable + record + 10);
        if (nameId != 1 && nameId != 16) continue;
        size_t start = static_cast<size_t>(stringOffset) + offset;
        if (start > nameSize || length > nameSize - start) continue;
        bool utf16 = platform == 3 || platform == 0;
        std::wstring text = DecodeFontName(nameTable + start, length, utf16);
        if (text.empty()) continue;
        int score = 0;
        if (nameId == 16) score += 100;
        if (platform == 3 && encoding == 1) score += 20;
        if (language == 0x0409 || language == 0x0419) score += 10;
        if (platform == 1) score += 2;
        if (score > bestScore) {
            bestScore = score;
            family = text;
        }
    }
    return family;
}

void EnsureEmbeddedFont() {
    if (g_fontResourceAttempted) return;
    g_fontResourceAttempted = true;
    HMODULE module = GetModuleHandleW(nullptr);
    HRSRC resource = FindResourceW(module, MAKEINTRESOURCEW(WATCHPROG_FONT_RESOURCE_ID),
                                  MAKEINTRESOURCEW(10));
    if (!resource) return;
    HGLOBAL loaded = LoadResource(module, resource);
    DWORD size = SizeofResource(module, resource);
    const BYTE* data = static_cast<const BYTE*>(LockResource(loaded));
    if (!data || size == 0) return;
    std::wstring family = ReadFamilyFromFont(data, size);
    DWORD fontCount = 0;
    HANDLE handle = AddFontMemResourceEx(const_cast<BYTE*>(data), size, nullptr, &fontCount);
    if (!handle || fontCount == 0) return;
    g_memFontHandle = handle;
    if (!family.empty()) g_uiFontFamily = family;
}

using SetPreferredAppModeFn = int(WINAPI*)(int);
using AllowDarkModeForWindowFn = BOOL(WINAPI*)(HWND, BOOL);
using FlushMenuThemesFn = void(WINAPI*)();
using RefreshImmersiveColorPolicyStateFn = void(WINAPI*)();

HMODULE g_uxtheme = nullptr;
SetPreferredAppModeFn g_setPreferredAppMode = nullptr;
AllowDarkModeForWindowFn g_allowDarkModeForWindow = nullptr;
FlushMenuThemesFn g_flushMenuThemes = nullptr;
RefreshImmersiveColorPolicyStateFn g_refreshImmersiveColorPolicyState = nullptr;
bool g_uxthemeLoaded = false;

void LoadUxTheme() {
    if (g_uxthemeLoaded) return;
    g_uxthemeLoaded = true;
    g_uxtheme = LoadLibraryW(L"uxtheme.dll");
    if (!g_uxtheme) return;
    g_setPreferredAppMode = reinterpret_cast<SetPreferredAppModeFn>(GetProcAddress(g_uxtheme, MAKEINTRESOURCEA(135)));
    g_allowDarkModeForWindow = reinterpret_cast<AllowDarkModeForWindowFn>(GetProcAddress(g_uxtheme, MAKEINTRESOURCEA(133)));
    g_flushMenuThemes = reinterpret_cast<FlushMenuThemesFn>(GetProcAddress(g_uxtheme, MAKEINTRESOURCEA(136)));
    g_refreshImmersiveColorPolicyState = reinterpret_cast<RefreshImmersiveColorPolicyStateFn>(GetProcAddress(g_uxtheme, MAKEINTRESOURCEA(104)));
}

DWORD ReadThemeValue(const wchar_t* name, DWORD fallback) {
    DWORD value = fallback;
    DWORD size = sizeof(value);
    if (RegGetValueW(HKEY_CURRENT_USER,
                     L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                     name, RRF_RT_REG_DWORD, nullptr, &value, &size) != ERROR_SUCCESS) {
        return fallback;
    }
    return value;
}

ThemeKind DetectKind() {
    HIGHCONTRASTW hc = {};
    hc.cbSize = sizeof(hc);
    if (SystemParametersInfoW(SPI_GETHIGHCONTRAST, sizeof(hc), &hc, 0) && (hc.dwFlags & HCF_HIGHCONTRASTON)) {
        return ThemeKind::HighContrast;
    }
    DWORD appLight = ReadThemeValue(L"AppsUseLightTheme", 1);
    if (appLight == 0) {
        DWORD systemLight = ReadThemeValue(L"SystemUsesLightTheme", 0);
        (void)systemLight;
        return ThemeKind::Dark;
    }
    return ThemeKind::Light;
}

void DestroyAssets() {
    HFONT* fonts[] = { &g_theme.fontUi, &g_theme.fontUiBold, &g_theme.fontUiUnderline,
                       &g_theme.fontTitle, &g_theme.fontSmall, &g_theme.fontMono };
    for (HFONT* font : fonts) {
        if (*font) { DeleteObject(*font); *font = nullptr; }
    }
    if (g_theme.windowBrush) { DeleteObject(g_theme.windowBrush); g_theme.windowBrush = nullptr; }
    if (g_theme.panelBrush) { DeleteObject(g_theme.panelBrush); g_theme.panelBrush = nullptr; }
}

HFONT MakeFont(int points, int weight, bool underline = false) {
    int height = -MulDiv(points, g_theme.dpi, 72);
    return CreateFontW(height, 0, 0, 0, weight, FALSE, underline ? TRUE : FALSE, FALSE, DEFAULT_CHARSET,
                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                       DEFAULT_PITCH | FF_DONTCARE, g_uiFontFamily.c_str());
}

void BuildAssets() {
    DestroyAssets();
    EnsureEmbeddedFont();
    g_theme.fontUi = MakeFont(10, FW_NORMAL);
    g_theme.fontUiBold = MakeFont(10, FW_BOLD);
    g_theme.fontUiUnderline = MakeFont(10, FW_NORMAL, true);
    g_theme.fontTitle = MakeFont(17, FW_BOLD);
    g_theme.fontSmall = MakeFont(9, FW_NORMAL);
    g_theme.fontMono = MakeFont(9, FW_NORMAL);
    g_theme.windowBrush = CreateSolidBrush(g_theme.windowBg);
    g_theme.panelBrush = CreateSolidBrush(g_theme.panelBg);
}

void SetPalette(ThemeKind kind) {
    g_theme.kind = kind;
    g_theme.dark = kind == ThemeKind::Dark;
    if (kind == ThemeKind::HighContrast) {
        g_theme.windowBg = GetSysColor(COLOR_WINDOW);
        g_theme.panelBg = GetSysColor(COLOR_WINDOW);
        g_theme.listBg = GetSysColor(COLOR_WINDOW);
        g_theme.text = GetSysColor(COLOR_WINDOWTEXT);
        g_theme.muted = GetSysColor(COLOR_GRAYTEXT);
        g_theme.border = GetSysColor(COLOR_WINDOWFRAME);
        g_theme.accent = GetSysColor(COLOR_HIGHLIGHT);
        g_theme.selectionBg = GetSysColor(COLOR_HIGHLIGHT);
        g_theme.selectionText = GetSysColor(COLOR_HIGHLIGHTTEXT);
        for (int i = 0; i < CatCount; ++i) g_theme.category[i] = g_theme.text;
        return;
    }
    if (kind == ThemeKind::Dark) {
        g_theme.windowBg = RGB(30, 32, 35);
        g_theme.panelBg = RGB(38, 41, 45);
        g_theme.listBg = RGB(26, 28, 31);
        g_theme.text = RGB(242, 244, 247);
        g_theme.muted = RGB(164, 172, 181);
        g_theme.border = RGB(60, 65, 72);
        g_theme.accent = RGB(92, 174, 255);
        g_theme.selectionBg = RGB(0, 95, 184);
        g_theme.selectionText = RGB(255, 255, 255);
        g_theme.category[CatFile] = RGB(103, 179, 255);
        g_theme.category[CatRegistry] = RGB(195, 157, 255);
        g_theme.category[CatTasks] = RGB(238, 184, 96);
        g_theme.category[CatProcess] = RGB(111, 212, 148);
        g_theme.category[CatNetwork] = RGB(94, 207, 224);
        g_theme.category[CatSystem] = RGB(176, 184, 193);
    } else {
        g_theme.windowBg = RGB(242, 244, 248);
        g_theme.panelBg = RGB(255, 255, 255);
        g_theme.listBg = RGB(255, 255, 255);
        g_theme.text = RGB(24, 28, 34);
        g_theme.muted = RGB(92, 102, 114);
        g_theme.border = RGB(198, 206, 216);
        g_theme.accent = RGB(0, 95, 184);
        g_theme.selectionBg = RGB(0, 120, 215);
        g_theme.selectionText = RGB(255, 255, 255);
        g_theme.category[CatFile] = RGB(0, 92, 175);
        g_theme.category[CatRegistry] = RGB(105, 57, 168);
        g_theme.category[CatTasks] = RGB(145, 87, 0);
        g_theme.category[CatProcess] = RGB(24, 107, 64);
        g_theme.category[CatNetwork] = RGB(0, 103, 124);
        g_theme.category[CatSystem] = RGB(95, 105, 117);
    }
}

void ApplyAppMode() {
    LoadUxTheme();
    if (!g_setPreferredAppMode) return;
    if (g_theme.kind == ThemeKind::Dark) g_setPreferredAppMode(2); // ForceDark
    else if (g_theme.kind == ThemeKind::Light) g_setPreferredAppMode(3); // ForceLight
    else g_setPreferredAppMode(0); // Default
    if (g_refreshImmersiveColorPolicyState) g_refreshImmersiveColorPolicyState();
    if (g_flushMenuThemes) g_flushMenuThemes();
}

void ApplyOnWindow(HWND hwnd) {
    if (!hwnd) return;
    BOOL dark = g_theme.dark ? TRUE : FALSE;
    DwmSetWindowAttribute(hwnd, 20, &dark, sizeof(dark));
    DwmSetWindowAttribute(hwnd, 19, &dark, sizeof(dark));
    LoadUxTheme();
    if (g_allowDarkModeForWindow) g_allowDarkModeForWindow(hwnd, dark);
    SetWindowTheme(hwnd, g_theme.dark ? L"DarkMode_Explorer" : L"Explorer", nullptr);
    DrawMenuBar(hwnd);
}

void ApplyTree(HWND root) {
    ApplyOnWindow(root);
    EnumChildWindows(root, [](HWND child, LPARAM) -> BOOL {
        SetWindowTheme(child, g_theme.dark ? L"DarkMode_Explorer" : L"Explorer", nullptr);
        SendMessageW(child, WM_THEMECHANGED, 0, 0);
        InvalidateRect(child, nullptr, TRUE);
        return TRUE;
    }, 0);
}

} // namespace

int Theme_CurrentDpi(HWND hwnd) {
    if (hwnd) {
        UINT dpi = GetDpiForWindow(hwnd);
        if (dpi >= 72) return static_cast<int>(dpi);
    }
    HDC dc = GetDC(nullptr);
    int dpi = 96;
    if (dc) {
        dpi = GetDeviceCaps(dc, LOGPIXELSX);
        ReleaseDC(nullptr, dc);
    }
    return dpi > 0 ? dpi : 96;
}

void Theme_Initialize(HWND hwnd) {
    g_theme.dpi = Theme_CurrentDpi(hwnd);
    SetPalette(DetectKind());
    BuildAssets();
    ApplyAppMode();
    ApplyTree(hwnd);
}

void Theme_Refresh(HWND hwnd) {
    int dpi = Theme_CurrentDpi(hwnd);
    ThemeKind kind = DetectKind();
    g_theme.dpi = dpi;
    SetPalette(kind);
    BuildAssets();
    ApplyAppMode();
    ApplyTree(hwnd);
    InvalidateRect(hwnd, nullptr, TRUE);
}

void Theme_Shutdown() {
    DestroyAssets();
    if (g_memFontHandle) {
        RemoveFontMemResourceEx(g_memFontHandle);
        g_memFontHandle = nullptr;
    }
}

const std::wstring& Theme_UiFontFamily() {
    return g_uiFontFamily;
}

void Theme_ApplyWindow(HWND hwnd) {
    ApplyOnWindow(hwnd);
}

void Theme_ApplyControls(HWND root) {
    ApplyTree(root);
}
