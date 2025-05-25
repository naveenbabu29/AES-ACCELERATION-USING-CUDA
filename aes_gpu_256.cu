#include <iostream>
#include <cuda_runtime.h>
#include <cstdlib>
#include <ctime>
#include <cstring>

#define BLOCK_SIZE 16
#define DATA_SIZE_MB 100
#define NUM_BLOCKS (DATA_SIZE_MB * 1024 * 1024 / 16)
#define ROUND_KEYS_SIZE 240
#define AES_ROUNDS 14

typedef unsigned char uint8_t;
using namespace std;

const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

const uint8_t inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

__constant__ uint8_t d_sbox[256];
__constant__ uint8_t d_inv_sbox[256];

//////////////////////////////////////////////////////
// Helper Functions for AES Transformations
//////////////////////////////////////////////////////

// SubBytes transformation: substitute each byte in the state using the S-box
__device__ void SubBytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = d_sbox[state[i]];
    }
}

// InvSubBytes transformation: substitute each byte in the state using the inverse S-box
__device__ void InvSubBytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = d_inv_sbox[state[i]];
    }
}

// ShiftRows transformation: cyclically shift rows of the state to the left
__device__ void ShiftRows(uint8_t* state) {
    uint8_t tmp;
    // Row 1: shift left by 1
    tmp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp;
    // Row 2: shift left by 2
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    // Row 3: shift left by 3
    tmp = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = tmp;
}

// InvShiftRows transformation: cyclically shift rows of the state to the right
__device__ void InvShiftRows(uint8_t* state) {
    uint8_t tmp;
    // Row 1: shift right by 1
    tmp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = tmp;
    // Row 2: shift right by 2
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    // Row 3: shift right by 3
    tmp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = tmp;
}

// AddRoundKey transformation: XOR the state with the round key
__device__ void AddRoundKey(uint8_t* state, const uint8_t* roundKey) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

// xtime: multiply by 2 in GF(2^8)
__device__ uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1B : 0x00);
}

// multiply: multiply two bytes in GF(2^8)
__device__ uint8_t multiply(uint8_t x, uint8_t y) {
    uint8_t result = 0;
    while (y) {
        if (y & 1) result ^= x;
        x = xtime(x);
        y >>= 1;
    }
    return result;
}

// MixColumns transformation: mix each column of the state matrix (encryption)
__device__ void MixColumns(uint8_t* state) {
    uint8_t temp[4];
    for (int i = 0; i < 4; i++) {
        temp[0] = multiply(0x02, state[i*4 + 0]) ^ multiply(0x03, state[i*4 + 1]) ^ state[i*4 + 2] ^ state[i*4 + 3];
        temp[1] = state[i*4 + 0] ^ multiply(0x02, state[i*4 + 1]) ^ multiply(0x03, state[i*4 + 2]) ^ state[i*4 + 3];
        temp[2] = state[i*4 + 0] ^ state[i*4 + 1] ^ multiply(0x02, state[i*4 + 2]) ^ multiply(0x03, state[i*4 + 3]);
        temp[3] = multiply(0x03, state[i*4 + 0]) ^ state[i*4 + 1] ^ state[i*4 + 2] ^ multiply(0x02, state[i*4 + 3]);
        for (int j = 0; j < 4; j++)
            state[i*4 + j] = temp[j];
    }
}

// InvMixColumns transformation: mix each column of the state matrix (decryption)
__device__ void InvMixColumns(uint8_t* state) {
    uint8_t temp[4];
    for (int i = 0; i < 4; i++) {
        temp[0] = multiply(0x0e, state[i*4 + 0]) ^ multiply(0x0b, state[i*4 + 1]) ^ multiply(0x0d, state[i*4 + 2]) ^ multiply(0x09, state[i*4 + 3]);
        temp[1] = multiply(0x09, state[i*4 + 0]) ^ multiply(0x0e, state[i*4 + 1]) ^ multiply(0x0b, state[i*4 + 2]) ^ multiply(0x0d, state[i*4 + 3]);
        temp[2] = multiply(0x0d, state[i*4 + 0]) ^ multiply(0x09, state[i*4 + 1]) ^ multiply(0x0e, state[i*4 + 2]) ^ multiply(0x0b, state[i*4 + 3]);
        temp[3] = multiply(0x0b, state[i*4 + 0]) ^ multiply(0x0d, state[i*4 + 1]) ^ multiply(0x09, state[i*4 + 2]) ^ multiply(0x0e, state[i*4 + 3]);
        for (int j = 0; j < 4; j++)
            state[i*4 + j] = temp[j];
    }
}

//////////////////////////////////////////////////////
// AES-256 Key Expansion (host-side)
//////////////////////////////////////////////////////

// KeyExpansion256: expands a 256-bit key into round keys for all AES rounds
void KeyExpansion256(const uint8_t* key, uint8_t* roundKeys) {
    const uint8_t Rcon[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};
    memcpy(roundKeys, key, 32); // Copy original key as first 8 words (32 bytes)
    uint8_t temp[4];
    int i = 8;
    int rconIdx = 0;

    while (i < 60) { // AES-256 needs 60 words (4 bytes each)
        for (int j = 0; j < 4; j++)
            temp[j] = roundKeys[(i - 1) * 4 + j];

        if (i % 8 == 0) {
            // Rotate, substitute, and XOR with Rcon for every 8th word
            uint8_t t = temp[0];
            temp[0] = sbox[temp[1]] ^ Rcon[rconIdx++];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
        } else if (i % 8 == 4) {
            // Substitute for every 4th word (except first)
            for (int j = 0; j < 4; j++)
                temp[j] = sbox[temp[j]];
        }

        // XOR with word 8 positions earlier
        for (int j = 0; j < 4; j++) {
            roundKeys[i * 4 + j] = roundKeys[(i - 8) * 4 + j] ^ temp[j];
        }
        i++;
    }
}

//////////////////////////////////////////////////////
// CUDA Kernels for AES-256 Encryption/Decryption
//////////////////////////////////////////////////////

// aes256_encrypt_kernel: encrypts each 16-byte block independently in parallel
__global__ void aes256_encrypt_kernel(uint8_t* input, uint8_t* output, const uint8_t* roundKeys) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= NUM_BLOCKS) return; // Out-of-bounds check

    uint8_t state[16];
    // Load input block into local state
    for (int i = 0; i < 16; i++) state[i] = input[idx * 16 + i];

    // Initial round key addition
    AddRoundKey(state, roundKeys);

    // Main AES rounds
    for (int round = 1; round < AES_ROUNDS; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 16);
    }
    // Final round (no MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + AES_ROUNDS * 16);

    // Store encrypted block to output
    for (int i = 0; i < 16; i++) output[idx * 16 + i] = state[i];
}

// aes256_decrypt_kernel: decrypts each 16-byte block independently in parallel
__global__ void aes256_decrypt_kernel(uint8_t* input, uint8_t* output, const uint8_t* roundKeys) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= NUM_BLOCKS) return; // Out-of-bounds check

    uint8_t state[16];
    // Load encrypted block into local state
    for (int i = 0; i < 16; i++) state[i] = input[idx * 16 + i];

    // Initial round key addition (last round key)
    AddRoundKey(state, roundKeys + AES_ROUNDS * 16);

    // Main AES rounds (in reverse)
    for (int round = AES_ROUNDS - 1; round > 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + round * 16);
        InvMixColumns(state);
    }
    // Final round (no InvMixColumns)
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys);

    // Store decrypted block to output
    for (int i = 0; i < 16; i++) output[idx * 16 + i] = state[i];
}

//////////////////////////////////////////////////////
// Main Program: AES-256 Batch Encryption/Decryption Test
//////////////////////////////////////////////////////
int main() {
    // Example 256-bit AES key (32 bytes)
    uint8_t key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    // Allocate host memory for input, encrypted, and decrypted data
    uint8_t* h_input = new uint8_t[NUM_BLOCKS * BLOCK_SIZE];
    uint8_t* h_encrypted = new uint8_t[NUM_BLOCKS * BLOCK_SIZE];
    uint8_t* h_decrypted = new uint8_t[NUM_BLOCKS * BLOCK_SIZE];
    uint8_t roundKeys[ROUND_KEYS_SIZE];

    // Fill input with random data
    srand(12345);
    for (int i = 0; i < NUM_BLOCKS * BLOCK_SIZE; i++)
        h_input[i] = rand() % 256;

    // Expand the key for all AES rounds
    KeyExpansion256(key, roundKeys);

    // Copy S-boxes to GPU constant memory
    cudaMemcpyToSymbol(d_sbox, sbox, 256);
    cudaMemcpyToSymbol(d_inv_sbox, inv_sbox, 256);

    // Allocate device memory
    uint8_t *d_input, *d_output, *d_decrypted, *d_roundKeys;
    cudaMalloc(&d_input, NUM_BLOCKS * BLOCK_SIZE);
    cudaMalloc(&d_output, NUM_BLOCKS * BLOCK_SIZE);
    cudaMalloc(&d_decrypted, NUM_BLOCKS * BLOCK_SIZE);
    cudaMalloc(&d_roundKeys, ROUND_KEYS_SIZE);

    // Set up CUDA kernel launch configuration
    dim3 blockDim(128); // 128 threads per block
    dim3 gridDim((NUM_BLOCKS + blockDim.x - 1) / blockDim.x); // Enough blocks to cover all data

    // CUDA events for timing
    cudaEvent_t start, stop;
    float time_total = 0, time_H2D = 0, time_encrypt = 0, time_decrypt = 0, time_D2H = 0;

    cudaEventCreate(&start);
    cudaEventCreate(&stop);

    cout << "\n[GPU] AES-256 Batch Encryption: " << NUM_BLOCKS << " blocks\n";

    // Copy input data and round keys from host to device (timed)
    cudaEventRecord(start);
    cudaMemcpy(d_input, h_input, NUM_BLOCKS * BLOCK_SIZE, cudaMemcpyHostToDevice);
    cudaMemcpy(d_roundKeys, roundKeys, ROUND_KEYS_SIZE, cudaMemcpyHostToDevice);
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&time_H2D, start, stop);

    // Launch encryption kernel (timed)
    cudaEventRecord(start);
    aes256_encrypt_kernel<<<gridDim, blockDim>>>(d_input, d_output, d_roundKeys);
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&time_encrypt, start, stop);

    // Launch decryption kernel (timed)
    cudaEventRecord(start);
    aes256_decrypt_kernel<<<gridDim, blockDim>>>(d_output, d_decrypted, d_roundKeys);
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&time_decrypt, start, stop);

    // Copy results back from device to host (timed)
    cudaEventRecord(start);
    cudaMemcpy(h_encrypted, d_output, NUM_BLOCKS * BLOCK_SIZE, cudaMemcpyDeviceToHost);
    cudaMemcpy(h_decrypted, d_decrypted, NUM_BLOCKS * BLOCK_SIZE, cudaMemcpyDeviceToHost);
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&time_D2H, start, stop);

    // Sum up total GPU time
    time_total = time_H2D + time_encrypt + time_decrypt + time_D2H;

    // Print timing breakdown
    printf("[GPU Timing Breakdown]\n");
    printf("  Host → Device Copy : %.3f ms\n", time_H2D);
    printf("  Encryption Kernel  : %.3f ms\n", time_encrypt);
    printf("  Decryption Kernel  : %.3f ms\n", time_decrypt);
    printf("  Device → Host Copy : %.3f ms\n", time_D2H);
    printf("  ------------------------------\n");
    printf("  Total GPU Time      : %.3f ms\n", time_total);

    // Verify that decrypted data matches original input
    bool match = true;
    for (int i = 0; i < NUM_BLOCKS * BLOCK_SIZE; i++) {
        if (h_input[i] != h_decrypted[i]) {
            printf("[✗] Mismatch at byte %d: input=%02x, decrypted=%02x\n", i, h_input[i], h_decrypted[i]);
            match = false;
            break;
        }
    }

    printf("%s\n", match ? "[✓] Decryption matches original plaintext." : "[✗] Decryption mismatch!");

    // Free device and host memory
    cudaFree(d_input);
    cudaFree(d_output);
    cudaFree(d_decrypted);
    cudaFree(d_roundKeys);
    delete[] h_input;
    delete[] h_encrypted;
    delete[] h_decrypted;

    return 0;
}