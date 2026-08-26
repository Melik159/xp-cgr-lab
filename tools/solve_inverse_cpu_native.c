
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    uint32_t h[5];
} sha1_state;

static inline uint32_t rol32(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32 - n));
}

static void sha1_compress_xval(const uint8_t xval[20], uint8_t out[20]) {
    uint32_t w[80];
    uint8_t block[64] = {0};
    memcpy(block, xval, 20);

    for (int t = 0; t < 16; t++) {
        w[t] = ((uint32_t)block[t*4] << 24) |
               ((uint32_t)block[t*4+1] << 16) |
               ((uint32_t)block[t*4+2] << 8) |
               ((uint32_t)block[t*4+3]);
    }
    for (int t = 16; t < 80; t++) {
        w[t] = rol32(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1);
    }

    uint32_t h0 = 0x67452301u, h1 = 0xEFCDAB89u, h2 = 0x98BADCFEu;
    uint32_t h3 = 0x10325476u, h4 = 0xC3D2E1F0u;
    uint32_t a=h0,b=h1,c=h2,d=h3,e=h4;

    for (int t = 0; t < 80; t++) {
        uint32_t f, k;
        if (t < 20) {
            f = (b & c) | ((~b) & d); k = 0x5A827999u;
        } else if (t < 40) {
            f = b ^ c ^ d; k = 0x6ED9EBA1u;
        } else if (t < 60) {
            f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu;
        } else {
            f = b ^ c ^ d; k = 0xCA62C1D6u;
        }
        uint32_t temp = rol32(a,5) + f + e + k + w[t];
        e=d; d=c; c=rol32(b,30); b=a; a=temp;
    }

    uint32_t hh[5] = {h0+a, h1+b, h2+c, h3+d, h4+e};
    for (int i = 0; i < 5; i++) {
        out[i*4]   = (uint8_t)(hh[i] >> 24);
        out[i*4+1] = (uint8_t)(hh[i] >> 16);
        out[i*4+2] = (uint8_t)(hh[i] >> 8);
        out[i*4+3] = (uint8_t)hh[i];
    }
}

static int hex20(const char *s, uint8_t out[20]) {
    if (strlen(s) != 40) return 0;
    for (int i = 0; i < 20; i++) {
        unsigned v;
        if (sscanf(s + i*2, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

static void print_hex20(const uint8_t x[20]) {
    for (int i = 0; i < 20; i++) printf("%02x", x[i]);
}

static void set_bit_be160(uint8_t x[20], int pos, int value) {
    int byte_from_right = pos / 8;
    int bit_in_byte = pos % 8;
    int idx = 19 - byte_from_right;
    uint8_t mask = (uint8_t)(1u << bit_in_byte);
    if (value) x[idx] |= mask;
    else x[idx] &= (uint8_t)~mask;
}

static void add160_be(const uint8_t a[20], const uint8_t b[20], uint8_t out[20]) {
    unsigned carry = 1; /* +1 */
    for (int i = 19; i >= 0; i--) {
        unsigned sum = (unsigned)a[i] + (unsigned)b[i] + carry;
        out[i] = (uint8_t)sum;
        carry = sum >> 8;
    }
}

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    if (argc != 7) {
        fprintf(stderr, "usage: %s K KNOWN_VALUE_HEX OUT_A_HEX OUT_B_HEX POSITIONS_CSV MAX_CANDIDATES\n", argv[0]);
        return 2;
    }

    int k = atoi(argv[1]);
    if (k <= 0 || k > 32) {
        fprintf(stderr, "FAIL: k must be 1..32\n");
        return 2;
    }

    uint8_t base[20], target_a[20], target_b[20];
    if (!hex20(argv[2], base) || !hex20(argv[3], target_a) || !hex20(argv[4], target_b)) {
        fprintf(stderr, "FAIL: malformed 20-byte hex argument\n");
        return 2;
    }

    int positions[32];
    char *tmp = strdup(argv[5]);
    if (!tmp) return 2;
    int npos = 0;
    for (char *tok = strtok(tmp, ","); tok; tok = strtok(NULL, ",")) {
        if (npos >= 32) { free(tmp); return 2; }
        positions[npos++] = atoi(tok);
    }
    free(tmp);
    if (npos != k) {
        fprintf(stderr, "FAIL: positions count=%d expected=%d\n", npos, k);
        return 2;
    }

    uint64_t search_space = (k == 32) ? (1ULL << 32) : (1ULL << k);
    uint64_t limit = strtoull(argv[6], NULL, 10);
    if (limit == 0 || limit > search_space) limit = search_space;

    printf("K=%d\n", k);
    printf("SEARCH_SPACE=%llu\n", (unsigned long long)search_space);
    printf("RUN_LIMIT=%llu\n", (unsigned long long)limit);

    double t0 = now_sec();
    uint64_t tested = 0;
    uint64_t found_counter = 0;
    uint8_t found[20];
    int found_flag = 0;

    for (uint64_t counter = 0; counter < limit; counter++) {
        uint8_t cand[20];
        memcpy(cand, base, 20);
        for (int j = 0; j < k; j++) {
            set_bit_be160(cand, positions[j], (int)((counter >> j) & 1ULL));
        }

        uint8_t outa[20];
        sha1_compress_xval(cand, outa);
        tested++;

        if (memcmp(outa, target_a, 20) != 0) continue;

        uint8_t xval_b[20], outb[20];
        add160_be(cand, outa, xval_b);
        sha1_compress_xval(xval_b, outb);
        if (memcmp(outb, target_b, 20) != 0) continue;

        memcpy(found, cand, 20);
        found_counter = counter;
        found_flag = 1;
        break;
    }

    double elapsed = now_sec() - t0;
    printf("TESTED=%llu\n", (unsigned long long)tested);
    printf("ELAPSED_SECONDS=%.9f\n", elapsed);
    printf("CANDIDATES_PER_SECOND=%.3f\n", elapsed > 0 ? tested / elapsed : 0.0);

    if (!found_flag) {
        printf("SEARCH_STATUS=%s\n", limit < search_space ? "BOUNDED_NO_SOLUTION" : "EXHAUSTED_NO_SOLUTION");
        return limit < search_space ? 3 : 1;
    }

    printf("SEARCH_STATUS=FOUND\n");
    printf("SOLUTION_COUNTER=%llu\n", (unsigned long long)found_counter);
    printf("SOLUTION_XVAL=");
    print_hex20(found);
    printf("\n");
    return 0;
}
