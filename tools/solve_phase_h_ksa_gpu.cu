#include <cuda_runtime.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <chrono>

__constant__ uint8_t C_BASE[80];
__constant__ uint8_t C_TARGET[256];
__constant__ int C_POSITIONS[32];

static inline void ck(cudaError_t e, const char *where) {
    if (e != cudaSuccess) {
        fprintf(stderr, "CUDA_FAIL %s: %s\n", where, cudaGetErrorString(e));
        exit(2);
    }
}

__device__ __forceinline__
bool rc4_ksa_match(uint64_t counter, int kbits) {
    uint8_t key[80];
    #pragma unroll
    for (int n = 0; n < 80; n++) key[n] = C_BASE[n];

    #pragma unroll 1
    for (int b = 0; b < kbits; b++) {
        if ((counter >> b) & 1ULL) {
            int pos = C_POSITIONS[b];
            int idx = 79 - (pos >> 3);
            key[idx] |= (uint8_t)(1u << (pos & 7));
        }
    }

    uint8_t s[256];
    #pragma unroll
    for (int n = 0; n < 256; n++) s[n] = (uint8_t)n;

    unsigned j = 0;
    #pragma unroll 1
    for (int i = 0; i < 256; i++) {
        j = (j + (unsigned)s[i] + (unsigned)key[i % 80]) & 0xffu;
        uint8_t tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }

    /* Most wrong candidates die on the first comparison. */
    if (s[0] != C_TARGET[0]) return false;
    #pragma unroll 1
    for (int n = 1; n < 256; n++) {
        if (s[n] != C_TARGET[n]) return false;
    }
    return true;
}

__global__
void search_kernel(uint64_t start, uint64_t count, int kbits,
                   unsigned long long *found_counter) {
    uint64_t off = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (off >= count) return;
    uint64_t counter = start + off;

    if (rc4_ksa_match(counter, kbits)) {
        atomicMin(found_counter, (unsigned long long)counter);
    }
}

static int parse_hex_n(const char *s, uint8_t *out, size_t n) {
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

static void reconstruct(uint64_t counter, int kbits,
                        const uint8_t base[80],
                        const int positions[32],
                        uint8_t out[80]) {
    memcpy(out, base, 80);
    for (int b = 0; b < kbits; b++) {
        if ((counter >> b) & 1ULL) {
            int pos = positions[b];
            int idx = 79 - (pos >> 3);
            out[idx] |= (uint8_t)(1u << (pos & 7));
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 7) {
        fprintf(stderr,
            "usage: %s K KNOWN_VALUE_HEX TARGET_POST_KSA_HEX "
            "POSITIONS_CSV CHUNK_SIZE BLOCK_SIZE\n", argv[0]);
        return 2;
    }

    int kbits = atoi(argv[1]);
    if (kbits <= 0 || kbits > 32) {
        fprintf(stderr, "FAIL k must be 1..32\n");
        return 2;
    }

    uint8_t base[80];
    uint8_t target258[258];
    if (!parse_hex_n(argv[2], base, 80) ||
        !parse_hex_n(argv[3], target258, 258)) {
        fprintf(stderr, "FAIL malformed hex input\n");
        return 2;
    }
    if (target258[256] != 0 || target258[257] != 0) {
        fprintf(stderr, "FAIL target post-KSA i/j must be 0/0\n");
        return 2;
    }

    int positions[32] = {0};
    char *copy = strdup(argv[4]);
    if (!copy) return 2;
    int npos = 0;
    for (char *tok = strtok(copy, ","); tok; tok = strtok(NULL, ",")) {
        if (npos >= 32) { free(copy); return 2; }
        int p = atoi(tok);
        if (p < 0 || p >= 640) {
            free(copy);
            fprintf(stderr, "FAIL invalid bit position %d\n", p);
            return 2;
        }
        positions[npos++] = p;
    }
    free(copy);
    if (npos != kbits) {
        fprintf(stderr, "FAIL positions count=%d expected=%d\n", npos, kbits);
        return 2;
    }

    uint64_t chunk = strtoull(argv[5], NULL, 10);
    if (chunk == 0) chunk = 1ULL << 22;
    int block = atoi(argv[6]);
    if (block <= 0 || block > 1024) block = 128;

    uint64_t search_space =
        (kbits == 32) ? (1ULL << 32) : (1ULL << kbits);

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
    printf("BLOCK_SIZE=%d\n", block);

    ck(cudaMemcpyToSymbol(C_BASE, base, sizeof(base)), "copy base");
    ck(cudaMemcpyToSymbol(C_TARGET, target258, 256), "copy target");
    ck(cudaMemcpyToSymbol(C_POSITIONS, positions, sizeof(positions)),
       "copy positions");

    unsigned long long *d_found = nullptr;
    ck(cudaMalloc(&d_found, sizeof(*d_found)), "cudaMalloc found");

    cudaEvent_t ev_start, ev_stop;
    ck(cudaEventCreate(&ev_start), "event create start");
    ck(cudaEventCreate(&ev_stop), "event create stop");

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

        uint64_t blocks64 = (count + (uint64_t)block - 1) / (uint64_t)block;
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

    uint8_t solution[80];
    reconstruct((uint64_t)found, kbits, base, positions, solution);

    printf("SEARCH_STATUS=FOUND\n");
    printf("SOLUTION_COUNTER=%llu\n", found);
    printf("SOLUTION_NEW_STATE=");
    print_hex(solution, 80);
    printf("\n");

    cudaFree(d_found);
    cudaEventDestroy(ev_start);
    cudaEventDestroy(ev_stop);
    return 0;
}
