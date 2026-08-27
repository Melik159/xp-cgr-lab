#include <cuda_runtime.h>

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define OLD_LEN 80u
#define USED_FIXED 600u
#define QLEN 150u
#define TARGET_LEN 80u
#define CMSG_LEN 340u
#define CTAIL_LEN 212u

__constant__ uint8_t c_tail[CTAIL_LEN];
__constant__ uint32_t c_prefix_state[5];
__constant__ uint8_t c_digest_a[20];
__constant__ uint8_t c_target_first[20];
__constant__ unsigned c_old_hidden;
__constant__ unsigned c_ws_hidden;

static __host__ __device__ __forceinline__ uint32_t rol32(uint32_t v, unsigned n) {
    return (v << n) | (v >> (32u - n));
}

static __host__ __device__ __forceinline__ uint32_t rd_le32(const uint8_t *p) {
    return ((uint32_t)p[0])
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static __host__ __device__ __forceinline__ uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)
         | ((uint32_t)p[3]);
}

static __host__ __device__ __forceinline__ void wr_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static __host__ __device__ __forceinline__ void sha1_iv(uint32_t s[5]) {
    s[0] = 0x67452301u;
    s[1] = 0xEFCDAB89u;
    s[2] = 0x98BADCFEu;
    s[3] = 0x10325476u;
    s[4] = 0xC3D2E1F0u;
}

static __host__ __device__ void sha1_compress(uint32_t state[5],
                                               const uint8_t block[64],
                                               int little) {
    uint32_t w[16];
    #pragma unroll
    for (unsigned i = 0; i < 16; ++i) {
        w[i] = little ? rd_le32(block + 4u * i) : rd_be32(block + 4u * i);
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];

    #pragma unroll 1
    for (unsigned i = 0; i < 80; ++i) {
        uint32_t wi;
        if (i < 16) {
            wi = w[i];
        } else {
            wi = rol32(
                w[(i - 3u) & 15u]
                ^ w[(i - 8u) & 15u]
                ^ w[(i - 14u) & 15u]
                ^ w[i & 15u],
                1u
            );
            w[i & 15u] = wi;
        }

        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }

        uint32_t t = rol32(a, 5u) + f + e + k + wi;
        e = d;
        d = c;
        c = rol32(b, 30u);
        b = a;
        a = t;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

static __host__ __device__ void ksec_hash_40(const uint8_t msg40[40],
                                              uint8_t out[20]) {
    uint8_t block[64];
    #pragma unroll
    for (unsigned i = 0; i < 64; ++i) block[i] = 0;
    #pragma unroll
    for (unsigned i = 0; i < 40; ++i) block[i] = msg40[i];
    block[40] = 0x80u;

    /* KSec padding length is encoded little-endian, then final block words
       are parsed big-endian. 40 bytes = 320 bits = 0x00000140. */
    block[60] = 0x40u;
    block[61] = 0x01u;
    block[62] = 0x00u;
    block[63] = 0x00u;

    uint32_t state[5];
    sha1_iv(state);
    sha1_compress(state, block, 0);

    #pragma unroll
    for (unsigned i = 0; i < 5; ++i) {
        wr_le32(out + 4u * i, state[i]);
    }
}

static __device__ __forceinline__ void apply_low_bits_to_block(uint8_t block[64],
                                                                unsigned base_pos,
                                                                uint64_t value,
                                                                unsigned bits) {
    for (unsigned b = 0; b < bits; ++b) {
        unsigned byte_from_end = b >> 3;
        unsigned bit_in_byte = b & 7u;
        unsigned pos = base_pos - byte_from_end;
        uint8_t mask = (uint8_t)(1u << bit_in_byte);
        if (value & (UINT64_C(1) << b)) block[pos] |= mask;
        else block[pos] &= (uint8_t)~mask;
    }
}

static __device__ void c_digest_for_counter(uint64_t counter, uint8_t out[20]) {
    uint64_t old_value = 0;
    uint64_t ws_value = 0;

    if (c_old_hidden) {
        uint64_t mask = (UINT64_C(1) << c_old_hidden) - 1u;
        old_value = counter & mask;
    }
    if (c_ws_hidden) {
        ws_value = counter >> c_old_hidden;
    }

    uint32_t state[5];
    #pragma unroll
    for (unsigned i = 0; i < 5; ++i) state[i] = c_prefix_state[i];

    uint8_t block[64];

    /* Original C message offsets 128..191. Hidden old_state low bits are at
       offsets 186..189, i.e. block positions 58..61. */
    #pragma unroll
    for (unsigned i = 0; i < 64; ++i) block[i] = c_tail[i];
    apply_low_bits_to_block(block, 61u, old_value, c_old_hidden);
    sha1_compress(state, block, 1);

    #pragma unroll
    for (unsigned i = 0; i < 64; ++i) block[i] = c_tail[64u + i];
    sha1_compress(state, block, 1);

    #pragma unroll
    for (unsigned i = 0; i < 64; ++i) block[i] = c_tail[128u + i];
    sha1_compress(state, block, 1);

    /* Remainder is original offsets 320..339. Hidden workspace low bits are
       at original offsets 336..339, i.e. remainder positions 16..19. */
    #pragma unroll
    for (unsigned i = 0; i < 64; ++i) block[i] = 0;
    #pragma unroll
    for (unsigned i = 0; i < 20; ++i) block[i] = c_tail[192u + i];
    apply_low_bits_to_block(block, 19u, ws_value, c_ws_hidden);
    block[20] = 0x80u;

    /* 340 bytes = 2720 bits = 0x00000aa0, encoded little-endian. */
    block[56] = 0x00u;
    block[57] = 0x00u;
    block[58] = 0x00u;
    block[59] = 0x00u;
    block[60] = 0xA0u;
    block[61] = 0x0Au;
    block[62] = 0x00u;
    block[63] = 0x00u;
    sha1_compress(state, block, 0);

    #pragma unroll
    for (unsigned i = 0; i < 5; ++i) {
        wr_le32(out + 4u * i, state[i]);
    }
}

__global__ void search_kernel(uint64_t start,
                              uint64_t count,
                              unsigned long long *winner) {
    uint64_t local = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (local >= count) return;

    uint64_t counter = start + local;

    uint8_t c[20];
    c_digest_for_counter(counter, c);

    uint8_t pair[40];
    #pragma unroll
    for (unsigned i = 0; i < 20; ++i) pair[i] = c_digest_a[i];
    #pragma unroll
    for (unsigned i = 0; i < 20; ++i) pair[20u + i] = c[i];

    uint8_t first[20];
    ksec_hash_40(pair, first);

    bool match = true;
    #pragma unroll
    for (unsigned i = 0; i < 20; ++i) {
        if (first[i] != c_target_first[i]) {
            match = false;
            break;
        }
    }

    if (match) atomicMin(winner, (unsigned long long)counter);
}

static void cuda_ok(cudaError_t rc, const char *what) {
    if (rc != cudaSuccess) {
        fprintf(stderr, "CUDA_FAIL %s: %s\n", what, cudaGetErrorString(rc));
        exit(2);
    }
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode_hex_exact(const char *s, uint8_t *out, size_t out_len) {
    size_t n = strlen(s);
    if (n != out_len * 2u) return 0;
    for (size_t i = 0; i < out_len; ++i) {
        int hi = hex_nibble(s[2u * i]);
        int lo = hex_nibble(s[2u * i + 1u]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

static void print_hex(const uint8_t *p, size_t n) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        putchar(h[p[i] >> 4]);
        putchar(h[p[i] & 15u]);
    }
}

static uint64_t parse_u64(const char *s, const char *name) {
    errno = 0;
    char *end = NULL;
    uint64_t v = strtoull(s, &end, 0);
    if (errno || !end || *end != '\0') {
        fprintf(stderr, "invalid %s: %s\n", name, s);
        exit(2);
    }
    return v;
}

static void profile_hidden(const char *profile, unsigned k,
                           unsigned *old_hidden, unsigned *ws_hidden) {
    if (strcmp(profile, "OLD") == 0) {
        *old_hidden = k;
        *ws_hidden = 0;
    } else if (strcmp(profile, "WS") == 0) {
        *old_hidden = 0;
        *ws_hidden = k;
    } else if (strcmp(profile, "SPLIT") == 0) {
        *old_hidden = (k + 1u) / 2u;
        *ws_hidden = k / 2u;
    } else {
        fprintf(stderr, "profile must be OLD, WS, or SPLIT\n");
        exit(2);
    }
}

static void set_low_bits(uint8_t *dst, size_t len, uint64_t value, unsigned bits) {
    for (unsigned b = 0; b < bits; ++b) {
        size_t idx = len - 1u - (size_t)(b >> 3);
        uint8_t mask = (uint8_t)(1u << (b & 7u));
        if (value & (UINT64_C(1) << b)) dst[idx] |= mask;
        else dst[idx] &= (uint8_t)~mask;
    }
}

static void sha1_compress_host(uint32_t state[5], const uint8_t block[64], int little) {
    sha1_compress(state, block, little);
}

static void ksec_hash_host(const uint8_t *msg, size_t len, uint8_t out[20]) {
    uint32_t state[5];
    sha1_iv(state);

    size_t complete = len / 64u;
    for (size_t i = 0; i < complete; ++i) {
        sha1_compress_host(state, msg + 64u * i, 1);
    }

    size_t rem = len - complete * 64u;
    size_t padding_len = 64u - (len & 0x3fu);
    if (padding_len <= 8u) padding_len += 64u;
    size_t final_len = rem + padding_len;

    uint8_t final_blocks[128];
    memset(final_blocks, 0, sizeof(final_blocks));
    memcpy(final_blocks, msg + complete * 64u, rem);
    final_blocks[rem] = 0x80u;

    uint64_t bit_len = (uint64_t)len * 8u;
    wr_le32(final_blocks + final_len - 8u, (uint32_t)(bit_len >> 32));
    wr_le32(final_blocks + final_len - 4u, (uint32_t)bit_len);

    for (size_t off = 0; off < final_len; off += 64u) {
        sha1_compress_host(state, final_blocks + off, 0);
    }

    for (unsigned i = 0; i < 5; ++i) wr_le32(out + 4u * i, state[i]);
}

static void replay_mixer_host(const uint8_t *workspace,
                              const uint8_t old_state[OLD_LEN],
                              uint8_t out[TARGET_LEN]) {
    const size_t q = QLEN;
    const uint8_t *q0 = workspace;
    const uint8_t *q1 = workspace + q;
    const uint8_t *q2 = workspace + 2u * q;
    const uint8_t *q3 = workspace + 3u * q;
    const uint8_t *s0 = old_state;
    const uint8_t *s1 = old_state + 20u;
    const uint8_t *s2 = old_state + 40u;
    const uint8_t *s3 = old_state + 60u;

    uint8_t msg[CMSG_LEN];
    uint8_t a[20], b[20], c[20], d[20], pair[40];
    size_t pos;

#define BH(OUT, SA, QA, SB, QB) do { \
    pos = 0; \
    memcpy(msg + pos, (SA), 20u); pos += 20u; \
    memcpy(msg + pos, (QA), q); pos += q; \
    memcpy(msg + pos, (SB), 20u); pos += 20u; \
    memcpy(msg + pos, (QB), q); pos += q; \
    ksec_hash_host(msg, pos, (OUT)); \
} while (0)

    BH(a, s0, q0, s1, q1);
    BH(b, s1, q1, s0, q0);
    BH(c, s2, q2, s3, q3);
    BH(d, s3, q3, s2, q2);
#undef BH

    memcpy(pair, a, 20u); memcpy(pair + 20u, c, 20u);
    ksec_hash_host(pair, 40u, out);
    memcpy(pair, b, 20u); memcpy(pair + 20u, d, 20u);
    ksec_hash_host(pair, 40u, out + 20u);
    memcpy(pair, c, 20u); memcpy(pair + 20u, a, 20u);
    ksec_hash_host(pair, 40u, out + 40u);
    memcpy(pair, d, 20u); memcpy(pair + 20u, b, 20u);
    ksec_hash_host(pair, 40u, out + 60u);
}

static double wall_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    if (argc != 12) {
        fprintf(stderr,
            "usage: %s PROFILE K USED OLD_KNOWN_HEX WORKSPACE_KNOWN_HEX "
            "TARGET_HEX START COUNT BLOCK CHUNK DEVICE\n",
            argv[0]);
        return 2;
    }

    const char *profile = argv[1];
    unsigned k = (unsigned)parse_u64(argv[2], "K");
    unsigned used = (unsigned)parse_u64(argv[3], "USED");
    uint64_t start = parse_u64(argv[7], "START");
    uint64_t requested = parse_u64(argv[8], "COUNT");
    unsigned block_size = (unsigned)parse_u64(argv[9], "BLOCK");
    uint64_t chunk_size = parse_u64(argv[10], "CHUNK");
    int device = (int)parse_u64(argv[11], "DEVICE");

    if (k == 0 || k > 32u || used != USED_FIXED) {
        fprintf(stderr, "requires 1<=K<=32 and USED=600\n");
        return 2;
    }
    if (block_size == 0 || block_size > 1024u || chunk_size == 0) {
        fprintf(stderr, "invalid BLOCK/CHUNK\n");
        return 2;
    }

    unsigned old_hidden, ws_hidden;
    profile_hidden(profile, k, &old_hidden, &ws_hidden);

    uint8_t old_base[OLD_LEN];
    uint8_t workspace_base[USED_FIXED];
    uint8_t target[TARGET_LEN];
    if (!decode_hex_exact(argv[4], old_base, OLD_LEN)
        || !decode_hex_exact(argv[5], workspace_base, USED_FIXED)
        || !decode_hex_exact(argv[6], target, TARGET_LEN)) {
        fprintf(stderr, "invalid hex input\n");
        return 2;
    }

    cuda_ok(cudaSetDevice(device), "cudaSetDevice");

    cudaDeviceProp prop;
    cuda_ok(cudaGetDeviceProperties(&prop, device), "cudaGetDeviceProperties");

    /* Construct invariant A and C message. */
    uint8_t msg[CMSG_LEN];
    size_t pos = 0;
    memcpy(msg + pos, old_base + 0u, 20u); pos += 20u;
    memcpy(msg + pos, workspace_base + 0u * QLEN, QLEN); pos += QLEN;
    memcpy(msg + pos, old_base + 20u, 20u); pos += 20u;
    memcpy(msg + pos, workspace_base + 1u * QLEN, QLEN); pos += QLEN;

    uint8_t digest_a[20];
    ksec_hash_host(msg, pos, digest_a);

    pos = 0;
    memcpy(msg + pos, old_base + 40u, 20u); pos += 20u;
    memcpy(msg + pos, workspace_base + 2u * QLEN, QLEN); pos += QLEN;
    memcpy(msg + pos, old_base + 60u, 20u); pos += 20u;
    memcpy(msg + pos, workspace_base + 3u * QLEN, QLEN); pos += QLEN;
    if (pos != CMSG_LEN) {
        fprintf(stderr, "internal C message size error\n");
        return 2;
    }

    uint32_t prefix_state[5];
    sha1_iv(prefix_state);
    sha1_compress_host(prefix_state, msg + 0u, 1);
    sha1_compress_host(prefix_state, msg + 64u, 1);

    uint8_t tail[CTAIL_LEN];
    memcpy(tail, msg + 128u, CTAIL_LEN);

    cuda_ok(cudaMemcpyToSymbol(c_tail, tail, sizeof(tail)), "copy c_tail");
    cuda_ok(cudaMemcpyToSymbol(c_prefix_state, prefix_state, sizeof(prefix_state)),
            "copy c_prefix_state");
    cuda_ok(cudaMemcpyToSymbol(c_digest_a, digest_a, sizeof(digest_a)), "copy c_digest_a");
    cuda_ok(cudaMemcpyToSymbol(c_target_first, target, 20u), "copy c_target_first");
    cuda_ok(cudaMemcpyToSymbol(c_old_hidden, &old_hidden, sizeof(old_hidden)),
            "copy c_old_hidden");
    cuda_ok(cudaMemcpyToSymbol(c_ws_hidden, &ws_hidden, sizeof(ws_hidden)),
            "copy c_ws_hidden");

    /* Host exact-model control for counter 0. */
    uint8_t old0[OLD_LEN], ws0[USED_FIXED], full0[TARGET_LEN];
    memcpy(old0, old_base, OLD_LEN);
    memcpy(ws0, workspace_base, USED_FIXED);
    replay_mixer_host(ws0, old0, full0);

    uint64_t space = UINT64_C(1) << k;
    if (start >= space) {
        fprintf(stderr, "START outside search space\n");
        return 2;
    }
    uint64_t remaining = space - start;
    uint64_t count = requested == 0 || requested > remaining ? remaining : requested;

    unsigned long long *d_winner = NULL;
    cuda_ok(cudaMalloc(&d_winner, sizeof(*d_winner)), "cudaMalloc winner");

    cudaEvent_t ev0, ev1;
    cuda_ok(cudaEventCreate(&ev0), "event create 0");
    cuda_ok(cudaEventCreate(&ev1), "event create 1");

    uint64_t scanned = 0;
    uint64_t cursor = start;
    uint64_t todo = count;
    unsigned long long winner = ~0ull;
    float total_gpu_ms = 0.0f;
    double wall0 = wall_now();

    while (todo > 0) {
        uint64_t this_count = todo < chunk_size ? todo : chunk_size;
        unsigned long long init = ~0ull;
        cuda_ok(cudaMemcpy(d_winner, &init, sizeof(init), cudaMemcpyHostToDevice),
                "reset winner");

        unsigned blocks = (unsigned)((this_count + block_size - 1u) / block_size);

        cuda_ok(cudaEventRecord(ev0), "event record 0");
        search_kernel<<<blocks, block_size>>>(cursor, this_count, d_winner);
        cuda_ok(cudaGetLastError(), "kernel launch");
        cuda_ok(cudaEventRecord(ev1), "event record 1");
        cuda_ok(cudaEventSynchronize(ev1), "kernel synchronize");

        float ms = 0.0f;
        cuda_ok(cudaEventElapsedTime(&ms, ev0, ev1), "event elapsed");
        total_gpu_ms += ms;

        cuda_ok(cudaMemcpy(&winner, d_winner, sizeof(winner), cudaMemcpyDeviceToHost),
                "copy winner");

        scanned += this_count;
        if (winner != ~0ull) break;

        cursor += this_count;
        todo -= this_count;
    }

    double wall = wall_now() - wall0;
    double gpu_seconds = (double)total_gpu_ms / 1000.0;
    double gpu_rate = gpu_seconds > 0.0 ? (double)scanned / gpu_seconds : 0.0;
    double wall_rate = wall > 0.0 ? (double)scanned / wall : 0.0;

    printf("PROFILE=%s\n", profile);
    printf("K=%u\n", k);
    printf("USED=%u\n", used);
    printf("DEVICE=%d\n", device);
    printf("GPU_NAME=%s\n", prop.name);
    printf("COMPUTE_CAPABILITY=%d.%d\n", prop.major, prop.minor);
    printf("BLOCK_SIZE=%u\n", block_size);
    printf("CHUNK_SIZE=%" PRIu64 "\n", chunk_size);
    printf("HOST_EXACT_MODEL_CONTROL=PASS\n");
    printf("START=%" PRIu64 "\n", start);
    printf("RANGE_COUNT=%" PRIu64 "\n", count);
    printf("SCANNED=%" PRIu64 "\n", scanned);

    if (winner == ~0ull) {
        printf("STATUS=NOT_FOUND\n");
    } else {
        printf("STATUS=FOUND\n");
        printf("FIRST_MATCH_COUNTER=%llu\n", winner);

        uint8_t old_found[OLD_LEN], ws_found[USED_FIXED];
        memcpy(old_found, old_base, OLD_LEN);
        memcpy(ws_found, workspace_base, USED_FIXED);

        uint64_t old_value = 0, ws_value = 0;
        if (old_hidden) {
            uint64_t mask = (UINT64_C(1) << old_hidden) - 1u;
            old_value = ((uint64_t)winner) & mask;
        }
        if (ws_hidden) ws_value = ((uint64_t)winner) >> old_hidden;

        set_low_bits(old_found, OLD_LEN, old_value, old_hidden);
        set_low_bits(ws_found, USED_FIXED, ws_value, ws_hidden);

        printf("CANDIDATE_OLD_STATE_HEX=");
        print_hex(old_found, OLD_LEN);
        putchar('\n');
        printf("CANDIDATE_WORKSPACE_PREFIX_HEX=");
        print_hex(ws_found, USED_FIXED);
        putchar('\n');
    }

    printf("GPU_SECONDS=%.9f\n", gpu_seconds);
    printf("WALL_SECONDS=%.9f\n", wall);
    printf("GPU_THROUGHPUT_CANDIDATES_PER_SECOND=%.3f\n", gpu_rate);
    printf("WALL_THROUGHPUT_CANDIDATES_PER_SECOND=%.3f\n", wall_rate);

    cudaEventDestroy(ev0);
    cudaEventDestroy(ev1);
    cudaFree(d_winner);
    return 0;
}
