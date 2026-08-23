#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <wincrypt.h>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_REPETITIONS 1UL
#define MAX_REPETITIONS 100000UL

#define API_CGR 0x01U
#define API_RTL 0x02U

typedef BOOLEAN (WINAPI *RTL_GEN_RANDOM_FN)(PVOID, ULONG);
typedef char function_pointer_size_check[
    sizeof(FARPROC) == sizeof(RTL_GEN_RANDOM_FN) ? 1 : -1];

static void print_usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s [--repetitions N] [--api cgr|rtl|both]\n"
            "       %s [N]\n",
            program, program);
}

static int parse_repetitions(const char *text, unsigned long *value)
{
    char *end;
    unsigned long parsed;

    if (text == NULL || text[0] == '\0' || text[0] == '-') {
        return 0;
    }

    errno = 0;
    end = NULL;
    parsed = strtoul(text, &end, 10);
    if (errno == ERANGE || end == text || *end != '\0' ||
        parsed < 1UL || parsed > MAX_REPETITIONS) {
        return 0;
    }

    *value = parsed;
    return 1;
}

static int parse_api(const char *text, unsigned int *api_mask)
{
    if (strcmp(text, "cgr") == 0) {
        *api_mask = API_CGR;
        return 1;
    }
    if (strcmp(text, "rtl") == 0) {
        *api_mask = API_RTL;
        return 1;
    }
    if (strcmp(text, "both") == 0) {
        *api_mask = API_CGR | API_RTL;
        return 1;
    }
    return 0;
}

static int parse_arguments(int argc, char **argv,
                           unsigned long *repetitions,
                           unsigned int *api_mask)
{
    int i;
    int positional_seen;

    *repetitions = DEFAULT_REPETITIONS;
    *api_mask = API_CGR | API_RTL;
    positional_seen = 0;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--repetitions") == 0 ||
            strcmp(argv[i], "-n") == 0) {
            if (++i >= argc || !parse_repetitions(argv[i], repetitions)) {
                return 0;
            }
        } else if (strcmp(argv[i], "--api") == 0) {
            if (++i >= argc || !parse_api(argv[i], api_mask)) {
                return 0;
            }
        } else if (strcmp(argv[i], "--help") == 0 ||
                   strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "/?") == 0) {
            print_usage(argv[0]);
            exit(0);
        } else if (!positional_seen && parse_repetitions(argv[i], repetitions)) {
            positional_seen = 1;
        } else {
            return 0;
        }
    }

    return 1;
}

static void bytes_to_hex(const BYTE *buffer, DWORD length, char *hex)
{
    static const char digits[] = "0123456789abcdef";
    DWORD i;

    for (i = 0; i < length; ++i) {
        hex[(size_t)i * 2U] = digits[(buffer[i] >> 4) & 0x0fU];
        hex[(size_t)i * 2U + 1U] = digits[buffer[i] & 0x0fU];
    }
    hex[(size_t)length * 2U] = '\0';
}

static int write_event(unsigned long event_id,
                       unsigned long iteration,
                       const char *api,
                       DWORD requested_length,
                       int success,
                       DWORD error_code,
                       const BYTE *buffer)
{
    SYSTEMTIME timestamp;
    char hex[(64U * 2U) + 1U];

    GetSystemTime(&timestamp);
    if (success) {
        bytes_to_hex(buffer, requested_length, hex);
    } else {
        hex[0] = '\0';
    }

    if (printf("{\"event_id\":%lu,\"iteration\":%lu,"
               "\"api\":\"%s\",\"requested_length\":%lu,"
               "\"success\":%s,\"win32_error\":%lu,"
               "\"bytes_hex\":\"%s\",\"pid\":%lu,\"tid\":%lu,"
               "\"timestamp_utc\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\"}\n",
               event_id,
               iteration,
               api,
               (unsigned long)requested_length,
               success ? "true" : "false",
               (unsigned long)error_code,
               hex,
               (unsigned long)GetCurrentProcessId(),
               (unsigned long)GetCurrentThreadId(),
               (unsigned int)timestamp.wYear,
               (unsigned int)timestamp.wMonth,
               (unsigned int)timestamp.wDay,
               (unsigned int)timestamp.wHour,
               (unsigned int)timestamp.wMinute,
               (unsigned int)timestamp.wSecond,
               (unsigned int)timestamp.wMilliseconds) < 0) {
        return 0;
    }

    return 1;
}

static int run_cgr_event(HCRYPTPROV provider,
                         DWORD provider_error,
                         unsigned long event_id,
                         unsigned long iteration,
                         DWORD length,
                         int *output_error)
{
    BYTE buffer[64];
    BOOL ok;
    DWORD error_code;

    memset(buffer, 0, sizeof(buffer));
    if (provider == (HCRYPTPROV)0) {
        ok = FALSE;
        error_code = provider_error;
    } else {
        SetLastError(ERROR_SUCCESS);
        ok = CryptGenRandom(provider, length, buffer);
        error_code = ok ? ERROR_SUCCESS : GetLastError();
    }

    if (!write_event(event_id, iteration, "CryptGenRandom", length,
                     ok != FALSE, error_code, buffer)) {
        *output_error = 1;
    }
    SecureZeroMemory(buffer, sizeof(buffer));
    return ok != FALSE;
}

static int run_rtl_event(RTL_GEN_RANDOM_FN rtl_gen_random,
                         DWORD resolution_error,
                         unsigned long event_id,
                         unsigned long iteration,
                         DWORD length,
                         int *output_error)
{
    BYTE buffer[64];
    BOOLEAN ok;
    DWORD error_code;

    memset(buffer, 0, sizeof(buffer));
    if (rtl_gen_random == NULL) {
        ok = FALSE;
        error_code = resolution_error;
    } else {
        SetLastError(ERROR_SUCCESS);
        ok = rtl_gen_random(buffer, (ULONG)length);
        error_code = ok ? ERROR_SUCCESS : GetLastError();
    }

    if (!write_event(event_id, iteration, "SystemFunction036", length,
                     ok != FALSE, error_code, buffer)) {
        *output_error = 1;
    }
    SecureZeroMemory(buffer, sizeof(buffer));
    return ok != FALSE;
}

int main(int argc, char **argv)
{
    unsigned long repetitions;
    unsigned int api_mask;
    unsigned long iteration;
    unsigned long event_id;
    HCRYPTPROV provider;
    DWORD provider_error;
    HMODULE advapi32;
    FARPROC resolved_proc;
    RTL_GEN_RANDOM_FN rtl_gen_random;
    DWORD resolution_error;
    int cgr_failed;
    int rtl_failed;
    int output_error;
    int exit_code;

    if (!parse_arguments(argc, argv, &repetitions, &api_mask)) {
        print_usage(argv[0]);
        return 64;
    }

    provider = (HCRYPTPROV)0;
    provider_error = ERROR_SUCCESS;
    if ((api_mask & API_CGR) != 0U) {
        SetLastError(ERROR_SUCCESS);
        if (!CryptAcquireContextA(&provider, NULL, NULL, PROV_RSA_FULL,
                                  CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
            provider_error = GetLastError();
            provider = (HCRYPTPROV)0;
        }
    }

    advapi32 = NULL;
    resolved_proc = NULL;
    rtl_gen_random = NULL;
    resolution_error = ERROR_SUCCESS;
    if ((api_mask & API_RTL) != 0U) {
        SetLastError(ERROR_SUCCESS);
        advapi32 = LoadLibraryA("advapi32.dll");
        if (advapi32 == NULL) {
            resolution_error = GetLastError();
        } else {
            SetLastError(ERROR_SUCCESS);
            resolved_proc = GetProcAddress(advapi32, "SystemFunction036");
            if (resolved_proc == NULL) {
                resolution_error = GetLastError();
                if (resolution_error == ERROR_SUCCESS) {
                    resolution_error = ERROR_PROC_NOT_FOUND;
                }
            } else {
                memcpy(&rtl_gen_random, &resolved_proc,
                       sizeof(rtl_gen_random));
            }
        }
    }

    event_id = 1UL;
    cgr_failed = 0;
    rtl_failed = 0;
    output_error = 0;
    for (iteration = 1UL; iteration <= repetitions; ++iteration) {
        if ((api_mask & API_CGR) != 0U) {
            if (!run_cgr_event(provider, provider_error, event_id++, iteration,
                               32U, &output_error)) {
                cgr_failed = 1;
            }
            if (!run_cgr_event(provider, provider_error, event_id++, iteration,
                               64U, &output_error)) {
                cgr_failed = 1;
            }
        }
        if ((api_mask & API_RTL) != 0U) {
            if (!run_rtl_event(rtl_gen_random, resolution_error, event_id++,
                               iteration, 32U, &output_error)) {
                rtl_failed = 1;
            }
            if (!run_rtl_event(rtl_gen_random, resolution_error, event_id++,
                               iteration, 64U, &output_error)) {
                rtl_failed = 1;
            }
        }
    }

    if (provider != (HCRYPTPROV)0) {
        SetLastError(ERROR_SUCCESS);
        if (!CryptReleaseContext(provider, 0U)) {
            fprintf(stderr, "CryptReleaseContext failed: GetLastError=%lu\n",
                    (unsigned long)GetLastError());
            output_error = 1;
        }
    }
    if (advapi32 != NULL) {
        SetLastError(ERROR_SUCCESS);
        if (!FreeLibrary(advapi32)) {
            fprintf(stderr, "FreeLibrary failed: GetLastError=%lu\n",
                    (unsigned long)GetLastError());
            output_error = 1;
        }
    }

    if (fflush(stdout) != 0 || ferror(stdout)) {
        fprintf(stderr, "stdout write failed\n");
        output_error = 1;
    }

    exit_code = 0;
    if (cgr_failed) {
        exit_code |= 1;
    }
    if (rtl_failed) {
        exit_code |= 2;
    }
    if (output_error) {
        exit_code |= 4;
    }
    return exit_code;
}
