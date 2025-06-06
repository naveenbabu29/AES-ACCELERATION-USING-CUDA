#include <iostream>
#include <cuda_runtime.h>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <chrono>
#include <thread>
#include <future>

#define BLOCK_SIZE 16
#define DATA_SIZE_MB 10
#define NUM_BLOCKS (DATA_SIZE_MB * 1024 * 1024 / 16)
#define ROUND_KEYS_SIZE 176

using namespace std;
typedef unsigned char uint8_t;

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


// Helper functions

__device__ void SubBytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = d_sbox[state[i]];
    }
}

__device__ void InvSubBytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = d_inv_sbox[state[i]];
    }
}

__device__ void ShiftRows(uint8_t* state) {
    uint8_t tmp;
    tmp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp;
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    tmp = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = tmp;
}

__device__ void InvShiftRows(uint8_t* state) {
    uint8_t tmp;
    tmp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = tmp;
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    tmp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = tmp;
}

__device__ void AddRoundKey(uint8_t* state, uint8_t* roundKey) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

__device__ uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1B : 0x00);
}

__device__ uint8_t multiply(uint8_t x, uint8_t y) {
    uint8_t result = 0;
    while (y) {
        if (y & 1) result ^= x;
        x = xtime(x);
        y >>= 1;
    }
    return result;
}

__device__ void MixColumns(uint8_t* state) {
    uint8_t temp[4];
    for (int i = 0; i < 4; i++) { // For each column
        temp[0] = multiply(0x02, state[i*4 + 0]) ^ multiply(0x03, state[i*4 + 1]) ^ state[i*4 + 2] ^ state[i*4 + 3];
        temp[1] = state[i*4 + 0] ^ multiply(0x02, state[i*4 + 1]) ^ multiply(0x03, state[i*4 + 2]) ^ state[i*4 + 3];
        temp[2] = state[i*4 + 0] ^ state[i*4 + 1] ^ multiply(0x02, state[i*4 + 2]) ^ multiply(0x03, state[i*4 + 3]);
        temp[3] = multiply(0x03, state[i*4 + 0]) ^ state[i*4 + 1] ^ state[i*4 + 2] ^ multiply(0x02, state[i*4 + 3]);
        for (int j = 0; j < 4; j++)
            state[i*4 + j] = temp[j];
    }
}

__device__ void InvMixColumns(uint8_t* state) {
    uint8_t temp[4];
    for (int i = 0; i < 4; i++) { // For each column
        temp[0] = multiply(0x0e, state[i*4 + 0]) ^ multiply(0x0b, state[i*4 + 1]) ^ multiply(0x0d, state[i*4 + 2]) ^ multiply(0x09, state[i*4 + 3]);
        temp[1] = multiply(0x09, state[i*4 + 0]) ^ multiply(0x0e, state[i*4 + 1]) ^ multiply(0x0b, state[i*4 + 2]) ^ multiply(0x0d, state[i*4 + 3]);
        temp[2] = multiply(0x0d, state[i*4 + 0]) ^ multiply(0x09, state[i*4 + 1]) ^ multiply(0x0e, state[i*4 + 2]) ^ multiply(0x0b, state[i*4 + 3]);
        temp[3] = multiply(0x0b, state[i*4 + 0]) ^ multiply(0x0d, state[i*4 + 1]) ^ multiply(0x09, state[i*4 + 2]) ^ multiply(0x0e, state[i*4 + 3]);
        for (int j = 0; j < 4; j++)
            state[i*4 + j] = temp[j];
    }
}


__global__ void aes128_encrypt_kernel(uint8_t* input, uint8_t* output, uint8_t* roundKeys) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= NUM_BLOCKS) return;

    uint8_t state[16];
    for (int i = 0; i < 16; i++) state[i] = input[idx * 16 + i];

    AddRoundKey(state, roundKeys);
    for (int round = 1; round < 10; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 16);
    }
    
    //final_round
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + 160);

    for (int i = 0; i < 16; i++) output[idx * 16 + i] = state[i];
}

__global__ void aes128_decrypt_kernel(uint8_t* input, uint8_t* output, uint8_t* roundKeys) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= NUM_BLOCKS) return;

    uint8_t state[16];
    for (int i = 0; i < 16; i++) state[i] = input[idx * 16 + i];

    AddRoundKey(state, roundKeys + 160);
    for (int round = 9; round > 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + round * 16);
        InvMixColumns(state);
    }
    //final round
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys);

    for (int i = 0; i < 16; i++) output[idx * 16 + i] = state[i];
}

void KeyExpansion(const uint8_t* key, uint8_t* roundKeys) {
    // Proper round constants for AES-128
    const uint8_t Rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
    
    // Copy the initial key (first 16 bytes)
    memcpy(roundKeys, key, 16);
    
    // Expand the key for the remaining 160 bytes (10 rounds, 16 bytes per round)
    for (int i = 4; i < 44; i++) {
        // Process one word (4 bytes) at a time
        uint8_t temp[4];
        
        // Get the previous word
        for (int j = 0; j < 4; j++) {
            temp[j] = roundKeys[(i-1)*4 + j];
        }
        
        // At the beginning of each round key (every 4th word)
        if (i % 4 == 0) {
            // RotWord - rotate left by one byte
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            
            // SubWord - substitute each byte using S-box
            for (int j = 0; j < 4; j++) {
                temp[j] = sbox[temp[j]];
            }
            
            // XOR with round constant (only first byte)
            temp[0] ^= Rcon[i/4 - 1];
        }
        
        // XOR with the word 4 positions back
        for (int j = 0; j < 4; j++) {
            roundKeys[i*4 + j] = roundKeys[(i-4)*4 + j] ^ temp[j];
        }
    }
}

void ascii_bomb(bool defused) {
    if (defused) {
        cout << "\n💣 Bomb Defused Just in Time!\n";
        cout << "    _____________\n";
        cout << "   |             |\n";
        cout << "   |   [SAFE]    |\n";
        cout << "   |_____________|\n";
    } else {
        cout << "\n💥 BOOM! The Bomb Exploded!\n";
        cout << "    _____________\n";
        cout << "   |             |\n";
        cout << "   |   [BOOM!]   |\n";
        cout << "   |_____________|\n";
    }
}


int main() {
    uint8_t* h_input = new uint8_t[NUM_BLOCKS * BLOCK_SIZE];
    uint8_t* h_output = new uint8_t[NUM_BLOCKS * BLOCK_SIZE];
    uint8_t* h_decrypted = new uint8_t[NUM_BLOCKS * BLOCK_SIZE];
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };
    uint8_t roundKeys[ROUND_KEYS_SIZE];
    KeyExpansion(key, roundKeys);
    cudaMemcpyToSymbol(d_sbox, sbox, 256);
    cudaMemcpyToSymbol(d_inv_sbox, inv_sbox, 256);

    srand(time(0));
    for (int i = 0; i < NUM_BLOCKS * BLOCK_SIZE; i++)
        h_input[i] = rand() % 256;

    uint8_t *d_input, *d_output, *d_decrypted, *d_roundKeys;
    cudaMalloc(&d_input, NUM_BLOCKS * BLOCK_SIZE);
    cudaMalloc(&d_output, NUM_BLOCKS * BLOCK_SIZE);
    cudaMalloc(&d_decrypted, NUM_BLOCKS * BLOCK_SIZE);
    cudaMalloc(&d_roundKeys, ROUND_KEYS_SIZE);

    cudaMemcpy(d_input, h_input, NUM_BLOCKS * BLOCK_SIZE, cudaMemcpyHostToDevice);
    cudaMemcpy(d_roundKeys, roundKeys, ROUND_KEYS_SIZE, cudaMemcpyHostToDevice);

    dim3 blockDim(256);
    dim3 gridDim((NUM_BLOCKS + blockDim.x - 1) / blockDim.x);

    const int countdown_ms = 500; // Bomb explodes after 150ms
    bool gpu_done = false;
    std::promise<float> time_result;
    std::future<float> time_future = time_result.get_future();

    auto bomb_thread = std::async(std::launch::async, [&]() {
        using namespace std::chrono_literals;
        for (int i = countdown_ms; i > 0; i -= 25) {
            if (gpu_done) return;
            cout << "[TIMER] " << i << " ms left...\n";
            this_thread::sleep_for(25ms);
        }
    });

    // Begin GPU encryption + decryption
    auto gpu_task = std::async(std::launch::async, [&]() {
        cudaEvent_t start, stop;
        cudaEventCreate(&start);
        cudaEventCreate(&stop);

        cudaEventRecord(start);
        aes128_encrypt_kernel<<<gridDim, blockDim>>>(d_input, d_output, d_roundKeys);
        aes128_decrypt_kernel<<<gridDim, blockDim>>>(d_output, d_decrypted, d_roundKeys);
        cudaEventRecord(stop);
        cudaEventSynchronize(stop);

        float total_time;
        cudaEventElapsedTime(&total_time, start, stop);
        time_result.set_value(total_time);

        cudaMemcpy(h_decrypted, d_decrypted, NUM_BLOCKS * BLOCK_SIZE, cudaMemcpyDeviceToHost);
        gpu_done = true;

        bool match = true;
        for (int i = 0; i < NUM_BLOCKS * BLOCK_SIZE; ++i) {
            if (h_input[i] != h_decrypted[i]) {
                match = false;
                break;
            }
        }

        return match;
    });

    bool decrypted_correct = gpu_task.get();
    float elapsed_gpu_time = time_future.get();
    cout << "\n[GPU] Encryption + Decryption Time: " << elapsed_gpu_time << " ms\n";

    bool defused = decrypted_correct && (elapsed_gpu_time <= countdown_ms);
    ascii_bomb(defused);

    cudaFree(d_input); cudaFree(d_output); cudaFree(d_decrypted); cudaFree(d_roundKeys);
    delete[] h_input; delete[] h_output; delete[] h_decrypted;
    return 0;
}
