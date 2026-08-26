#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int hex_n(const char *s, uint8_t *out, size_t n) {
    if (strlen(s) != n * 2) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + i * 2, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

static void print_hex(const uint8_t *x, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", x[i]);
}

static void set_bit_be640(uint8_t x[80], int pos, int value) {
    int byte_from_right = pos / 8;
    int bit_in_byte = pos % 8;
    int idx = 79 - byte_from_right;
    uint8_t mask = (uint8_t)(1u << bit_in_byte);
    if (value) x[idx] |= mask;
    else x[idx] &= (uint8_t)~mask;
}

static int rc4_ksa_matches(const uint8_t key[80], const uint8_t target[256]) {
    uint8_t s[256];
    for (int i = 0; i < 256; i++) s[i] = (uint8_t)i;

    unsigned j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % 80]) & 0xffu;
        uint8_t tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }
    return memcmp(s, target, 256) == 0;
}

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr,
            "usage: %s K KNOWN_VALUE_HEX TARGET_POST_KSA_HEX "
            "POSITIONS_CSV MAX_CANDIDATES\n", argv[0]);
        return 2;
    }

    int k = atoi(argv[1]);
    if (k <= 0 || k > 32) {
        fprintf(stderr, "FAIL: k must be 1..32\n");
        return 2;
    }

    uint8_t base[80];
    uint8_t target258[258];
    if (!hex_n(argv[2], base, 80)) {
        fprintf(stderr, "FAIL: malformed 80-byte known value\n");
        return 2;
    }
    if (!hex_n(argv[3], target258, 258)) {
        fprintf(stderr, "FAIL: malformed 258-byte target\n");
        return 2;
    }
    if (target258[256] != 0 || target258[257] != 0) {
        fprintf(stderr, "FAIL: target post-KSA i/j must be 0/0\n");
        return 2;
    }

    int positions[32];
    char *tmp = strdup(argv[4]);
    if (!tmp) return 2;
    int npos = 0;
    for (char *tok = strtok(tmp, ","); tok; tok = strtok(NULL, ",")) {
        if (npos >= 32) {
            free(tmp);
            return 2;
        }
        int p = atoi(tok);
        if (p < 0 || p >= 640) {
            free(tmp);
            fprintf(stderr, "FAIL: invalid bit position %d\n", p);
            return 2;
        }
        positions[npos++] = p;
    }
    free(tmp);

    if (npos != k) {
        fprintf(stderr, "FAIL: positions count=%d expected=%d\n", npos, k);
        return 2;
    }

    uint64_t search_space = (k == 32) ? (1ULL << 32) : (1ULL << k);
    uint64_t limit = strtoull(argv[5], NULL, 10);
    if (limit == 0 || limit > search_space) limit = search_space;

    printf("K=%d\n", k);
    printf("SEARCH_SPACE=%llu\n", (unsigned long long)search_space);
    printf("RUN_LIMIT=%llu\n", (unsigned long long)limit);

    double t0 = now_sec();
    uint64_t tested = 0;
    uint64_t found_counter = 0;
    uint8_t found[80];
    int found_flag = 0;

    for (uint64_t counter = 0; counter < limit; counter++) {
        uint8_t cand[80];
        memcpy(cand, base, 80);

        for (int b = 0; b < k; b++) {
            set_bit_be640(cand, positions[b],
                          (int)((counter >> b) & 1ULL));
        }

        tested++;
        if (!rc4_ksa_matches(cand, target258)) continue;

        memcpy(found, cand, 80);
        found_counter = counter;
        found_flag = 1;
        break;
    }

    double elapsed = now_sec() - t0;
    printf("TESTED=%llu\n", (unsigned long long)tested);
    printf("ELAPSED_SECONDS=%.9f\n", elapsed);
    printf("CANDIDATES_PER_SECOND=%.3f\n",
           elapsed > 0.0 ? tested / elapsed : 0.0);

    if (!found_flag) {
        printf("SEARCH_STATUS=%s\n",
               limit < search_space
               ? "BOUNDED_NO_SOLUTION"
               : "EXHAUSTED_NO_SOLUTION");
        return limit < search_space ? 3 : 1;
    }

    printf("SEARCH_STATUS=FOUND\n");
    printf("SOLUTION_COUNTER=%llu\n",
           (unsigned long long)found_counter);
    printf("SOLUTION_NEW_STATE=");
    print_hex(found, 80);
    printf("\n");
    return 0;
}
