#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <wincrypt.h>

#include <stdio.h>
#include <string.h>

typedef BOOL (WINAPI *CGR_FN)(HCRYPTPROV, DWORD, BYTE *);
typedef BOOLEAN (WINAPI *RTL_FN)(PVOID, ULONG);
typedef FARPROC (WINAPI *GETPROC_FN)(HMODULE, LPCSTR);

typedef char cgr_pointer_size_check[sizeof(CGR_FN) == sizeof(DWORD) ? 1 : -1];
typedef char rtl_pointer_size_check[sizeof(RTL_FN) == sizeof(DWORD) ? 1 : -1];
typedef char getproc_pointer_size_check[sizeof(GETPROC_FN) == sizeof(DWORD) ? 1 : -1];

static CGR_FN g_real_cgr = NULL;
static RTL_FN g_real_rtl = NULL;
static GETPROC_FN g_real_getproc = NULL;
static CRITICAL_SECTION g_log_lock;
static LONG g_cgr_event_id = 0;
static LONG g_rtl_event_id = 0;
static char g_cgr_log[MAX_PATH];
static char g_rtl_log[MAX_PATH];
static char g_status_log[MAX_PATH];

static const char *base_name(const char *path)
{
    const char *name;
    const char *cursor;

    name = path;
    cursor = path;
    while (*cursor != '\0') {
        if (*cursor == '\\' || *cursor == '/') {
            name = cursor + 1;
        }
        ++cursor;
    }
    return name;
}

static int write_all(HANDLE file, const void *buffer, DWORD length)
{
    const BYTE *cursor;
    DWORD remaining;

    cursor = (const BYTE *)buffer;
    remaining = length;
    while (remaining != 0U) {
        DWORD written;

        written = 0U;
        if (!WriteFile(file, cursor, remaining, &written, NULL) || written == 0U) {
            return 0;
        }
        cursor += written;
        remaining -= written;
    }
    return 1;
}

static int append_text(const char *path, const char *text)
{
    HANDLE file;
    DWORD length;
    int ok;

    if (path[0] == '\0') {
        return 0;
    }

    file = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return 0;
    }
    if (SetFilePointer(file, 0L, NULL, FILE_END) == INVALID_SET_FILE_POINTER &&
        GetLastError() != ERROR_SUCCESS) {
        CloseHandle(file);
        return 0;
    }
    length = (DWORD)strlen(text);
    ok = write_all(file, text, length);
    if (!CloseHandle(file)) {
        ok = 0;
    }
    return ok;
}

static void module_for_address(void *address,
                               char *module_name,
                               DWORD module_name_size,
                               DWORD *module_base,
                               DWORD *module_offset)
{
    MEMORY_BASIC_INFORMATION memory;
    HMODULE module;
    char module_path[MAX_PATH];
    DWORD address_value;

    module_name[0] = '\0';
    *module_base = 0U;
    *module_offset = 0U;
    memset(&memory, 0, sizeof(memory));
    if (VirtualQuery(address, &memory, sizeof(memory)) == 0U ||
        memory.AllocationBase == NULL) {
        lstrcpynA(module_name, "<unknown>", (int)module_name_size);
        return;
    }

    module = (HMODULE)memory.AllocationBase;
    module_path[0] = '\0';
    if (GetModuleFileNameA(module, module_path, MAX_PATH) == 0U) {
        lstrcpynA(module_name, "<unknown>", (int)module_name_size);
    } else {
        lstrcpynA(module_name, base_name(module_path), (int)module_name_size);
    }

    *module_base = (DWORD)(ULONG_PTR)module;
    address_value = (DWORD)(ULONG_PTR)address;
    if (address_value >= *module_base) {
        *module_offset = address_value - *module_base;
    }
}

static void process_name(char *name, DWORD name_size)
{
    char path[MAX_PATH];

    path[0] = '\0';
    if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0U) {
        lstrcpynA(name, "<unknown>", (int)name_size);
    } else {
        lstrcpynA(name, base_name(path), (int)name_size);
    }
}

static void write_trace_event(const char *path,
                              const char *event_prefix,
                              LONG event_number,
                              const char *api,
                              DWORD requested_length,
                              const BYTE *buffer,
                              int success,
                              DWORD error_code,
                              void *return_address)
{
    SYSTEMTIME timestamp;
    char proc_name[MAX_PATH];
    char caller_module[MAX_PATH];
    DWORD caller_base;
    DWORD caller_offset;
    char prefix[1400];
    char suffix[8];
    HANDLE file;
    DWORD i;
    int prefix_length;
    int ok;
    static const char digits[] = "0123456789abcdef";

    GetSystemTime(&timestamp);
    process_name(proc_name, MAX_PATH);
    module_for_address(return_address, caller_module, MAX_PATH,
                       &caller_base, &caller_offset);

    prefix_length = sprintf(
        prefix,
        "{\"event_id\":\"%s_%06ld\",\"namespace\":\"%s\","
        "\"api\":\"%s\","
        "\"timestamp_utc\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\","
        "\"pid\":%lu,\"tid\":%lu,\"process_name\":\"%s\","
        "\"requested_length\":%lu,\"buffer_address\":\"0x%08lx\","
        "\"return_address\":\"0x%08lx\",\"caller_module\":\"%s\","
        "\"caller_module_base\":\"0x%08lx\","
        "\"caller_offset\":\"0x%08lx\",\"success\":%s,"
        "\"win32_error\":%lu,\"returned_bytes_hex\":\"",
        event_prefix,
        event_number,
        event_prefix,
        api,
        (unsigned int)timestamp.wYear,
        (unsigned int)timestamp.wMonth,
        (unsigned int)timestamp.wDay,
        (unsigned int)timestamp.wHour,
        (unsigned int)timestamp.wMinute,
        (unsigned int)timestamp.wSecond,
        (unsigned int)timestamp.wMilliseconds,
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        proc_name,
        (unsigned long)requested_length,
        (unsigned long)(ULONG_PTR)buffer,
        (unsigned long)(ULONG_PTR)return_address,
        caller_module,
        (unsigned long)caller_base,
        (unsigned long)caller_offset,
        success ? "true" : "false",
        (unsigned long)error_code);
    if (prefix_length < 0 || prefix_length >= (int)sizeof(prefix)) {
        return;
    }
    lstrcpyA(suffix, "\"}\r\n");

    EnterCriticalSection(&g_log_lock);
    file = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_log_lock);
        return;
    }
    ok = 1;
    SetLastError(ERROR_SUCCESS);
    if (SetFilePointer(file, 0L, NULL, FILE_END) == INVALID_SET_FILE_POINTER &&
        GetLastError() != ERROR_SUCCESS) {
        ok = 0;
    }
    if (ok) {
        ok = write_all(file, prefix, (DWORD)prefix_length);
    }
    if (ok && success) {
        for (i = 0U; i < requested_length; ++i) {
            char pair[2];

            pair[0] = digits[(buffer[i] >> 4) & 0x0fU];
            pair[1] = digits[buffer[i] & 0x0fU];
            if (!write_all(file, pair, 2U)) {
                ok = 0;
                break;
            }
        }
    }
    if (ok) {
        write_all(file, suffix, (DWORD)strlen(suffix));
    }
    CloseHandle(file);
    LeaveCriticalSection(&g_log_lock);
}

static BOOL WINAPI hook_cgr(HCRYPTPROV provider, DWORD length, BYTE *buffer)
{
    void *return_address;
    LONG event_number;
    BOOL result;
    DWORD error_code;

    return_address = __builtin_return_address(0);
    event_number = InterlockedIncrement(&g_cgr_event_id);
    result = g_real_cgr(provider, length, buffer);
    error_code = result ? ERROR_SUCCESS : GetLastError();
    write_trace_event(g_cgr_log, "CGR", event_number, "CryptGenRandom",
                      length, buffer, result != FALSE, error_code,
                      return_address);
    SetLastError(error_code);
    return result;
}

static BOOLEAN WINAPI hook_rtl(PVOID buffer, ULONG length)
{
    void *return_address;
    LONG event_number;
    BOOLEAN result;
    DWORD error_code;

    return_address = __builtin_return_address(0);
    event_number = InterlockedIncrement(&g_rtl_event_id);
    result = g_real_rtl(buffer, length);
    error_code = result ? ERROR_SUCCESS : GetLastError();
    write_trace_event(g_rtl_log, "RTL", event_number, "SystemFunction036",
                      (DWORD)length, (const BYTE *)buffer, result != FALSE,
                      error_code, return_address);
    SetLastError(error_code);
    return result;
}

static FARPROC WINAPI hook_get_proc_address(HMODULE module, LPCSTR name)
{
    FARPROC resolved;

    resolved = g_real_getproc(module, name);
    if (((ULONG_PTR)name >> 16) != 0U &&
        strcmp(name, "SystemFunction036") == 0 && resolved != NULL) {
        DWORD value;
        RTL_FN replacement;
        FARPROC returned;

        value = 0U;
        memcpy(&value, &resolved, sizeof(value));
        memcpy(&g_real_rtl, &value, sizeof(g_real_rtl));
        replacement = hook_rtl;
        memcpy(&returned, &replacement, sizeof(returned));
        return returned;
    }
    return resolved;
}

static int patch_import(HMODULE image,
                        const char *dll_name,
                        const char *function_name,
                        DWORD replacement,
                        DWORD *original)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_IMPORT_DESCRIPTOR *descriptor;
    BYTE *base;

    base = (BYTE *)image;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
            .VirtualAddress == 0U) {
        return 0;
    }

    descriptor = (IMAGE_IMPORT_DESCRIPTOR *)(base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
            .VirtualAddress);
    while (descriptor->Name != 0U) {
        const char *import_dll;

        import_dll = (const char *)(base + descriptor->Name);
        if (lstrcmpiA(import_dll, dll_name) == 0 &&
            descriptor->OriginalFirstThunk != 0U) {
            IMAGE_THUNK_DATA *names;
            IMAGE_THUNK_DATA *addresses;

            names = (IMAGE_THUNK_DATA *)(base + descriptor->OriginalFirstThunk);
            addresses = (IMAGE_THUNK_DATA *)(base + descriptor->FirstThunk);
            while (names->u1.AddressOfData != 0U) {
                if (!IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal)) {
                    IMAGE_IMPORT_BY_NAME *import_name;

                    import_name = (IMAGE_IMPORT_BY_NAME *)(base +
                        names->u1.AddressOfData);
                    if (strcmp((const char *)import_name->Name,
                               function_name) == 0) {
                        DWORD old_protection;
                        DWORD ignored;
                        DWORD *slot;

                        slot = &addresses->u1.Function;
                        if (!VirtualProtect(slot, sizeof(*slot),
                                            PAGE_READWRITE,
                                            &old_protection)) {
                            return 0;
                        }
                        *original = *slot;
                        *slot = replacement;
                        FlushInstructionCache(GetCurrentProcess(), slot,
                                              sizeof(*slot));
                        if (!VirtualProtect(slot, sizeof(*slot),
                                            old_protection, &ignored)) {
                            return 0;
                        }
                        return 1;
                    }
                }
                ++names;
                ++addresses;
            }
        }
        ++descriptor;
    }
    return 0;
}

static int install_hooks(void)
{
    HMODULE image;
    CGR_FN cgr_replacement;
    GETPROC_FN getproc_replacement;
    DWORD cgr_value;
    DWORD getproc_value;
    DWORD original_cgr;
    DWORD original_getproc;
    int cgr_ok;
    int getproc_ok;
    char status[320];

    image = GetModuleHandleA(NULL);
    cgr_replacement = hook_cgr;
    getproc_replacement = hook_get_proc_address;
    cgr_value = 0U;
    getproc_value = 0U;
    original_cgr = 0U;
    original_getproc = 0U;
    memcpy(&cgr_value, &cgr_replacement, sizeof(cgr_value));
    memcpy(&getproc_value, &getproc_replacement, sizeof(getproc_value));

    cgr_ok = patch_import(image, "ADVAPI32.dll", "CryptGenRandom",
                          cgr_value, &original_cgr);
    getproc_ok = patch_import(image, "KERNEL32.dll", "GetProcAddress",
                              getproc_value, &original_getproc);
    if (cgr_ok) {
        memcpy(&g_real_cgr, &original_cgr, sizeof(g_real_cgr));
    }
    if (getproc_ok) {
        memcpy(&g_real_getproc, &original_getproc, sizeof(g_real_getproc));
    }

    sprintf(status,
            "{\"phase\":\"attach\",\"pid\":%lu,"
            "\"cryptgenrandom_iat_hook\":%s,"
            "\"getprocaddress_iat_hook\":%s}\r\n",
            (unsigned long)GetCurrentProcessId(),
            cgr_ok ? "true" : "false",
            getproc_ok ? "true" : "false");
    append_text(g_status_log, status);
    return cgr_ok && getproc_ok;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        InitializeCriticalSection(&g_log_lock);
        g_cgr_log[0] = '\0';
        g_rtl_log[0] = '\0';
        g_status_log[0] = '\0';
        GetEnvironmentVariableA("CGR_J2_CGR_LOG", g_cgr_log, MAX_PATH);
        GetEnvironmentVariableA("CGR_J2_RTL_LOG", g_rtl_log, MAX_PATH);
        GetEnvironmentVariableA("CGR_J2_STATUS_LOG", g_status_log, MAX_PATH);
        install_hooks();
    } else if (reason == DLL_PROCESS_DETACH) {
        DeleteCriticalSection(&g_log_lock);
    }
    return TRUE;
}
