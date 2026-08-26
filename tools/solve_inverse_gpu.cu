#include <cuda_runtime.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <chrono>
#include <string>
#include <vector>

__constant__ uint32_t C_BASE[5];
__constant__ uint32_t C_TARGET_A[5];
__constant__ uint32_t C_TARGET_B[5];
__constant__ int C_POSITIONS[32];

static inline void ck(cudaError_t e, const char *where) {
    if (e != cudaSuccess) {
        fprintf(stderr, "CUDA_FAIL %s: %s\n", where, cudaGetErrorString(e));
        exit(2);
    }
}

__device__ __forceinline__ uint32_t rol32(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32 - n));
}

__device__ __forceinline__
void G_words(const uint32_t x[5], uint32_t out[5]) {
    uint32_t w[16];
    #pragma unroll
    for (int i = 0; i < 5; i++) w[i] = x[i];
    #pragma unroll
    for (int i = 5; i < 16; i++) w[i] = 0;

    uint32_t a = 0x67452301u;
    uint32_t b = 0xEFCDAB89u;
    uint32_t c = 0x98BADCFEu;
    uint32_t d = 0x10325476u;
    uint32_t e = 0xC3D2E1F0u;

    #pragma unroll 1
    for (int t = 0; t < 80; t++) {
        uint32_t wt;
        if (t < 16) {
            wt = w[t];
        } else {
            int q = t & 15;
            wt = rol32(
                w[(t - 3) & 15] ^
                w[(t - 8) & 15] ^
                w[(t - 14) & 15] ^
                w[q], 1
            );
            w[q] = wt;
        }

        uint32_t f, k;
        if (t < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999u;
        } else if (t < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if (t < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }

        uint32_t temp = rol32(a, 5) + f + e + k + wt;
        e = d;
        d = c;
        c = rol32(b, 30);
        b = a;
        a = temp;
    }

    out[0] = 0x67452301u + a;
    out[1] = 0xEFCDAB89u + b;
    out[2] = 0x98BADCFEu + c;
    out[3] = 0x10325476u + d;
    out[4] = 0xC3D2E1F0u + e;
}

__device__ __forceinline__
void add160_plus1(const uint32_t a[5], const uint32_t b[5], uint32_t out[5]) {
    uint64_t carry = 1;
    #pragma unroll
    for (int i = 4; i >= 0; i--) {
        uint64_t s = (uint64_t)a[i] + (uint64_t)b[i] + carry;
        out[i] = (uint32_t)s;
        carry = s >> 32;
    }
}

__global__
void search_kernel(uint64_t start, uint64_t count, int kbits,
                   unsigned long long *found_counter) {
    uint64_t off = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (off >= count) return;
    uint64_t counter = start + off;

    uint32_t x[5];
    #pragma unroll
    for (int i = 0; i < 5; i++) x[i] = C_BASE[i];

    #pragma unroll 1
    for (int j = 0; j < kbits; j++) {
        if ((counter >> j) & 1ULL) {
            int pos = C_POSITIONS[j];
            int wi = 4 - (pos >> 5);
            int bi = pos & 31;
            x[wi] |= (1u << bi);
        }
    }

    uint32_t outa[5];
    G_words(x, outa);

    #pragma unroll
    for (int i = 0; i < 5; i++) {
        if (outa[i] != C_TARGET_A[i]) return;
    }

    uint32_t xb[5], outb[5];
    add160_plus1(x, outa, xb);
    G_words(xb, outb);

    #pragma unroll
    for (int i = 0; i < 5; i++) {
        if (outb[i] != C_TARGET_B[i]) return;
    }

    atomicMin(found_counter, (unsigned long long)counter);
}

static int parse_hex160(const char *s, uint32_t out[5]) {
    if (strlen(s) != 40) return 0;
    for (int i = 0; i < 5; i++) {
        char tmp[9];
        memcpy(tmp, s + i * 8, 8);
        tmp[8] = 0;
        char *end = nullptr;
        unsigned long v = strtoul(tmp, &end, 16);
        if (!end || *end) return 0;
        out[i] = (uint32_t)v;
    }
    return 1;
}

static void print_hex160(const uint32_t x[5]) {
    for (int i = 0; i < 5; i++) printf("%08x", x[i]);
}

static void reconstruct(uint64_t counter, int kbits,
                        const uint32_t base[5],
                        const int positions[32],
                        uint32_t out[5]) {
    for (int i = 0; i < 5; i++) out[i] = base[i];
    for (int j = 0; j < kbits; j++) {
        if ((counter >> j) & 1ULL) {
            int pos = positions[j];
            int wi = 4 - (pos >> 5);
            int bi = pos & 31;
            out[wi] |= (1u << bi);
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 7) {
        fprintf(stderr,
            "usage: %s K KNOWN_VALUE_HEX OUT_A_HEX OUT_B_HEX POSITIONS_CSV CHUNK_SIZE\n",
            argv[0]);
        return 2;
    }

    int kbits = atoi(argv[1]);
    if (kbits <= 0 || kbits > 32) {
        fprintf(stderr, "FAIL k must be 1..32\n");
        return 2;
    }

    uint32_t base[5], ta[5], tb[5];
    if (!parse_hex160(argv[2], base) ||
        !parse_hex160(argv[3], ta) ||
        !parse_hex160(argv[4], tb)) {
        fprintf(stderr, "FAIL malformed 160-bit hex input\n");
        return 2;
    }

    int positions[32] = {0};
    char *copy = strdup(argv[5]);
    if (!copy) return 2;
    int npos = 0;
    for (char *tok = strtok(copy, ","); tok; tok = strtok(nullptr, ",")) {
        if (npos >= 32) { free(copy); return 2; }
        positions[npos++] = atoi(tok);
    }
    free(copy);
    if (npos != kbits) {
        fprintf(stderr, "FAIL positions count=%d expected=%d\n", npos, kbits);
        return 2;
    }

    uint64_t chunk = strtoull(argv[6], nullptr, 10);
    if (chunk == 0) chunk = 1ULL << 24;

    uint64_t search_space = (kbits == 32) ? (1ULL << 32) : (1ULL << kbits);

    int dev = 0;
    ck(cudaSetDevice(dev), "cudaSetDevice");
    cudaDeviceProp prop{};
    ck(cudaGetDeviceProperties(&prop, dev), "cudaGetDeviceProperties");

    printf("GPU_NAME=%s\n", prop.name);
    printf("COMPUTE_CAPABILITY=%d.%d\n", prop.major, prop.minor);
    printf("MULTIPROCESSORS=%d\n", prop.multiProcessorCount);
    printf("INSTANCE_K=%d\n", kbits);
    printf("SEARCH_SPACE=%llu\n", (unsigned long long)search_space);
    printf("CHUNK_SIZE=%llu\n", (unsigned long long)chunk);

    ck(cudaMemcpyToSymbol(C_BASE, base, sizeof(base)), "copy base");
    ck(cudaMemcpyToSymbol(C_TARGET_A, ta, sizeof(ta)), "copy target_a");
    ck(cudaMemcpyToSymbol(C_TARGET_B, tb, sizeof(tb)), "copy target_b");
    ck(cudaMemcpyToSymbol(C_POSITIONS, positions, sizeof(positions)), "copy positions");

    unsigned long long *d_found = nullptr;
    ck(cudaMalloc(&d_found, sizeof(*d_found)), "cudaMalloc found");

    cudaEvent_t ev_start, ev_stop;
    ck(cudaEventCreate(&ev_start), "event create start");
    ck(cudaEventCreate(&ev_stop), "event create stop");

    const int block = 256;
    uint64_t scanned = 0;
    double gpu_seconds = 0.0;
    unsigned long long found = 0xFFFFFFFFFFFFFFFFULL;

    auto wall0 = std::chrono::steady_clock::now();

    for (uint64_t start = 0; start < search_space; start += chunk) {
        uint64_t count = chunk;
        if (count > search_space - start) count = search_space - start;

        unsigned long long init = 0xFFFFFFFFFFFFFFFFULL;
        ck(cudaMemcpy(d_found, &init, sizeof(init), cudaMemcpyHostToDevice),
           "reset found");

        uint64_t blocks64 = (count + block - 1) / block;
        if (blocks64 > 2147483647ULL) {
            fprintf(stderr, "FAIL grid too large\n");
            return 2;
        }

        ck(cudaEventRecord(ev_start), "event start");
        search_kernel<<<(unsigned)blocks64, block>>>(
            start, count, kbits, d_found
        );
        ck(cudaGetLastError(), "kernel launch");
        ck(cudaEventRecord(ev_stop), "event stop");
        ck(cudaEventSynchronize(ev_stop), "event sync");

        float ms = 0.0f;
        ck(cudaEventElapsedTime(&ms, ev_start, ev_stop), "event elapsed");
        gpu_seconds += (double)ms / 1000.0;

        ck(cudaMemcpy(&found, d_found, sizeof(found), cudaMemcpyDeviceToHost),
           "copy found");

        scanned += count;
        if (found != 0xFFFFFFFFFFFFFFFFULL) break;
    }

    auto wall1 = std::chrono::steady_clock::now();
    double wall_seconds =
        std::chrono::duration<double>(wall1 - wall0).count();

    printf("SCANNED=%llu\n", (unsigned long long)scanned);
    printf("GPU_SECONDS=%.9f\n", gpu_seconds);
    printf("WALL_SECONDS=%.9f\n", wall_seconds);
    printf("CANDIDATES_PER_SECOND=%.3f\n",
           gpu_seconds > 0 ? (double)scanned / gpu_seconds : 0.0);

    if (found == 0xFFFFFFFFFFFFFFFFULL) {
        printf("SEARCH_STATUS=EXHAUSTED_NO_SOLUTION\n");
        cudaFree(d_found);
        cudaEventDestroy(ev_start);
        cudaEventDestroy(ev_stop);
        return 1;
    }

    uint32_t solution[5];
    reconstruct((uint64_t)found, kbits, base, positions, solution);

    printf("SEARCH_STATUS=FOUND\n");
    printf("SOLUTION_COUNTER=%llu\n", found);
    printf("SOLUTION_XVAL=");
    print_hex160(solution);
    printf("\n");

    cudaFree(d_found);
    cudaEventDestroy(ev_start);
    cudaEventDestroy(ev_stop);
    return 0;
}
