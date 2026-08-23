#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN

#include <windows.h>

#include <stdio.h>
#include <string.h>

#define MODE_CONTROL 0
#define MODE_TRACE 1
#define COMMAND_LINE_SIZE 4096

static void usage(const char *program)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s control STDOUT STDERR METRICS PROGRAM [ARGS...]\n"
        "  %s trace STDOUT STDERR METRICS CGR_LOG RTL_LOG STATUS_LOG PROGRAM [ARGS...]\n",
        program, program);
}

static int append_argument(char *command, DWORD capacity, const char *argument)
{
    DWORD used;
    DWORD needed;
    const char *cursor;

    used = (DWORD)strlen(command);
    needed = 3U;
    cursor = argument;
    while (*cursor != '\0') {
        needed += (*cursor == '"') ? 2U : 1U;
        ++cursor;
    }
    if (used + needed >= capacity) {
        return 0;
    }
    if (used != 0U) {
        command[used++] = ' ';
    }
    command[used++] = '"';
    cursor = argument;
    while (*cursor != '\0') {
        if (*cursor == '"') {
            command[used++] = '\\';
        }
        command[used++] = *cursor++;
    }
    command[used++] = '"';
    command[used] = '\0';
    return 1;
}

static int sibling_dll_path(char *path, DWORD capacity)
{
    DWORD length;
    char *cursor;
    char *last_separator;
    const char dll_name[] = "cgr_trace.dll";

    length = GetModuleFileNameA(NULL, path, capacity);
    if (length == 0U || length >= capacity) {
        return 0;
    }
    last_separator = NULL;
    cursor = path;
    while (*cursor != '\0') {
        if (*cursor == '\\' || *cursor == '/') {
            last_separator = cursor;
        }
        ++cursor;
    }
    if (last_separator == NULL ||
        (DWORD)(last_separator - path + 1) + (DWORD)strlen(dll_name) >= capacity) {
        return 0;
    }
    lstrcpyA(last_separator + 1, dll_name);
    return 1;
}

static int inject_dll(HANDLE process, const char *dll_path, DWORD *error_code)
{
    SIZE_T path_size;
    LPVOID remote_path;
    SIZE_T written;
    HMODULE kernel32;
    FARPROC load_library_proc;
    LPTHREAD_START_ROUTINE thread_start;
    HANDLE thread;
    DWORD thread_result;
    int ok;

    path_size = strlen(dll_path) + 1U;
    remote_path = VirtualAllocEx(process, NULL, path_size,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote_path == NULL) {
        *error_code = GetLastError();
        return 0;
    }

    written = 0U;
    if (!WriteProcessMemory(process, remote_path, dll_path, path_size,
                            &written) || written != path_size) {
        *error_code = GetLastError();
        VirtualFreeEx(process, remote_path, 0U, MEM_RELEASE);
        return 0;
    }

    kernel32 = GetModuleHandleA("kernel32.dll");
    load_library_proc = GetProcAddress(kernel32, "LoadLibraryA");
    if (load_library_proc == NULL) {
        *error_code = GetLastError();
        VirtualFreeEx(process, remote_path, 0U, MEM_RELEASE);
        return 0;
    }
    memcpy(&thread_start, &load_library_proc, sizeof(thread_start));
    thread = CreateRemoteThread(process, NULL, 0U, thread_start, remote_path,
                                0U, NULL);
    if (thread == NULL) {
        *error_code = GetLastError();
        VirtualFreeEx(process, remote_path, 0U, MEM_RELEASE);
        return 0;
    }

    ok = 1;
    if (WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0) {
        *error_code = GetLastError();
        ok = 0;
    }
    thread_result = 0U;
    if (ok && (!GetExitCodeThread(thread, &thread_result) || thread_result == 0U)) {
        *error_code = GetLastError();
        if (*error_code == ERROR_SUCCESS) {
            *error_code = ERROR_DLL_INIT_FAILED;
        }
        ok = 0;
    }
    CloseHandle(thread);
    VirtualFreeEx(process, remote_path, 0U, MEM_RELEASE);
    return ok;
}

static ULONGLONG elapsed_us(const LARGE_INTEGER *start,
                            const LARGE_INTEGER *end,
                            const LARGE_INTEGER *frequency)
{
    ULONGLONG ticks;

    ticks = (ULONGLONG)(end->QuadPart - start->QuadPart);
    return (ticks * 1000000ULL) / (ULONGLONG)frequency->QuadPart;
}

static void u64_to_decimal(ULONGLONG value, char *text)
{
    char reversed[32];
    DWORD count;
    DWORD i;

    count = 0U;
    do {
        reversed[count++] = (char)('0' + (value % 10U));
        value /= 10U;
    } while (value != 0U);
    for (i = 0U; i < count; ++i) {
        text[i] = reversed[count - i - 1U];
    }
    text[count] = '\0';
}

static int write_metrics(const char *path,
                         const char *mode,
                         DWORD pid,
                         DWORD child_exit_code,
                         int injection_success,
                         DWORD injection_error,
                         ULONGLONG setup_us,
                         ULONGLONG execution_us,
                         ULONGLONG total_us)
{
    HANDLE file;
    char json[640];
    char setup_text[32];
    char execution_text[32];
    char total_text[32];
    int length;
    DWORD written;

    u64_to_decimal(setup_us, setup_text);
    u64_to_decimal(execution_us, execution_text);
    u64_to_decimal(total_us, total_text);
    length = sprintf(
        json,
        "{\"mode\":\"%s\",\"pid\":%lu,\"child_exit_code\":%lu,"
        "\"injection_success\":%s,\"injection_error\":%lu,"
        "\"setup_us\":%s,\"execution_us\":%s,"
        "\"total_us\":%s}\r\n",
        mode,
        (unsigned long)pid,
        (unsigned long)child_exit_code,
        injection_success ? "true" : "false",
        (unsigned long)injection_error,
        setup_text,
        execution_text,
        total_text);
    if (length < 0 || length >= (int)sizeof(json)) {
        return 0;
    }
    file = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return 0;
    }
    written = 0U;
    if (!WriteFile(file, json, (DWORD)length, &written, NULL) ||
        written != (DWORD)length) {
        CloseHandle(file);
        return 0;
    }
    return CloseHandle(file) != FALSE;
}

int main(int argc, char **argv)
{
    int mode;
    int program_index;
    const char *stdout_path;
    const char *stderr_path;
    const char *metrics_path;
    char command_line[COMMAND_LINE_SIZE];
    char dll_path[MAX_PATH];
    SECURITY_ATTRIBUTES security;
    HANDLE child_stdout;
    HANDLE child_stderr;
    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    LARGE_INTEGER frequency;
    LARGE_INTEGER total_start;
    LARGE_INTEGER execution_start;
    LARGE_INTEGER end;
    DWORD injection_error;
    DWORD child_exit_code;
    DWORD wait_result;
    int injection_success;
    int i;
    int runner_result;

    if (argc < 2) {
        usage(argv[0]);
        return 64;
    }
    if (strcmp(argv[1], "control") == 0) {
        if (argc < 6) {
            usage(argv[0]);
            return 64;
        }
        mode = MODE_CONTROL;
        program_index = 5;
    } else if (strcmp(argv[1], "trace") == 0) {
        mode = MODE_TRACE;
        program_index = 8;
        if (argc < 9) {
            usage(argv[0]);
            return 64;
        }
    } else {
        usage(argv[0]);
        return 64;
    }

    stdout_path = argv[2];
    stderr_path = argv[3];
    metrics_path = argv[4];
    command_line[0] = '\0';
    for (i = program_index; i < argc; ++i) {
        if (!append_argument(command_line, COMMAND_LINE_SIZE, argv[i])) {
            fprintf(stderr, "Child command line is too long\n");
            return 65;
        }
    }

    if (mode == MODE_TRACE) {
        if (!SetEnvironmentVariableA("CGR_J2_CGR_LOG", argv[5]) ||
            !SetEnvironmentVariableA("CGR_J2_RTL_LOG", argv[6]) ||
            !SetEnvironmentVariableA("CGR_J2_STATUS_LOG", argv[7]) ||
            !sibling_dll_path(dll_path, MAX_PATH)) {
            fprintf(stderr, "Cannot prepare trace environment: GetLastError=%lu\n",
                    (unsigned long)GetLastError());
            return 66;
        }
    }

    memset(&security, 0, sizeof(security));
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;
    child_stdout = CreateFileA(stdout_path, GENERIC_WRITE, FILE_SHARE_READ,
                               &security, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (child_stdout == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Cannot create child stdout: GetLastError=%lu\n",
                (unsigned long)GetLastError());
        return 67;
    }
    child_stderr = CreateFileA(stderr_path, GENERIC_WRITE, FILE_SHARE_READ,
                               &security, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (child_stderr == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Cannot create child stderr: GetLastError=%lu\n",
                (unsigned long)GetLastError());
        CloseHandle(child_stdout);
        return 68;
    }

    memset(&startup, 0, sizeof(startup));
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = child_stdout;
    startup.hStdError = child_stderr;
    memset(&process, 0, sizeof(process));
    if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0 ||
        !QueryPerformanceCounter(&total_start)) {
        fprintf(stderr, "High-resolution timer unavailable: GetLastError=%lu\n",
                (unsigned long)GetLastError());
        CloseHandle(child_stderr);
        CloseHandle(child_stdout);
        return 69;
    }
    execution_start = total_start;
    end = total_start;
    if (!CreateProcessA(NULL, command_line, NULL, NULL, TRUE,
                        CREATE_SUSPENDED, NULL, NULL, &startup, &process)) {
        fprintf(stderr, "CreateProcess failed: GetLastError=%lu\n",
                (unsigned long)GetLastError());
        CloseHandle(child_stderr);
        CloseHandle(child_stdout);
        return 70;
    }
    CloseHandle(child_stderr);
    CloseHandle(child_stdout);

    injection_error = ERROR_SUCCESS;
    injection_success = 1;
    if (mode == MODE_TRACE) {
        injection_success = inject_dll(process.hProcess, dll_path,
                                       &injection_error);
    }
    if (!injection_success) {
        fprintf(stderr, "DLL injection failed: GetLastError=%lu\n",
                (unsigned long)injection_error);
        TerminateProcess(process.hProcess, 70U);
        wait_result = WaitForSingleObject(process.hProcess, INFINITE);
        if (wait_result != WAIT_OBJECT_0 && injection_error == ERROR_SUCCESS) {
            injection_error = wait_result == WAIT_FAILED
                ? GetLastError() : ERROR_GEN_FAILURE;
        }
    } else {
        if (!QueryPerformanceCounter(&execution_start)) {
            injection_success = 0;
            injection_error = GetLastError();
            TerminateProcess(process.hProcess, 71U);
        }
        if (injection_success &&
            ResumeThread(process.hThread) == (DWORD)-1) {
            injection_success = 0;
            injection_error = GetLastError();
            TerminateProcess(process.hProcess, 72U);
        }
        wait_result = WaitForSingleObject(process.hProcess, INFINITE);
        if (wait_result != WAIT_OBJECT_0) {
            injection_success = 0;
            injection_error = wait_result == WAIT_FAILED
                ? GetLastError() : ERROR_GEN_FAILURE;
        }
    }
    if (!QueryPerformanceCounter(&end)) {
        end = execution_start;
        injection_success = 0;
        injection_error = GetLastError();
    }

    child_exit_code = 73U;
    if (!GetExitCodeProcess(process.hProcess, &child_exit_code)) {
        injection_success = 0;
        injection_error = GetLastError();
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (!injection_success) {
        execution_start = end;
    }

    runner_result = 0;
    if (!write_metrics(metrics_path,
                       mode == MODE_TRACE ? "trace" : "control",
                       process.dwProcessId,
                       child_exit_code,
                       injection_success,
                       injection_error,
                       elapsed_us(&total_start, &execution_start, &frequency),
                       elapsed_us(&execution_start, &end, &frequency),
                       elapsed_us(&total_start, &end, &frequency))) {
        fprintf(stderr, "Cannot write metrics: GetLastError=%lu\n",
                (unsigned long)GetLastError());
        runner_result = 74;
    } else if (!injection_success) {
        runner_result = 75;
    } else if (child_exit_code != 0U) {
        runner_result = (int)(child_exit_code & 0xffU);
    }
    return runner_result;
}
