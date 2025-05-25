#include <iostream>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <chrono>

using namespace std;
using namespace std::chrono;

const int Nb = 4;       // Number of 32-bit words in block (128 bits / 32 = 4)
const int Nk = 8;       // AES-256 key length = 256 bits = 8 words
const int Nr = 14;      // AES-256 has 14 rounds

#define DATA_SIZE_MB 100
#define NUM_BLOCKS (DATA_SIZE_MB * 1024 * 1024 / 16)
#define AES_ROUNDS 14

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

// Round constants for key expansion
uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36
};

/// Helper functions///////////

/**
 * Generates random plaintext data for encryption.
 * @param data 2D array to fill with random bytes (each row is a 16-byte block)
 * @param count Number of blocks to generate
 */
void generatePlaintext(uint8_t (*data)[16], int count) {
    srand(12345); // Fixed seed for reproducibility
    for (int i = 0; i < count; ++i) {
        for (int j = 0; j < 16; ++j) {
            data[i][j] = rand() % 256;
        }
    }
}

/**
 * Applies the AES S-box to each byte in the state (SubBytes step)
 */
void SubBytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
}

/**
 * Applies the AES inverse S-box to each byte in the state (InvSubBytes step)
 */
void InvSubBytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) state[i] = inv_sbox[state[i]];
}

/**
 * Performs the AES ShiftRows operation (row-wise byte shifting)
 */
void ShiftRows(uint8_t* state) {
    uint8_t tmp;
    // Row 1: shift left by 1
    tmp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp;
    // Row 2: shift left by 2
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    // Row 3: shift left by 3
    tmp = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = tmp;
}

/**
 * Performs the AES inverse ShiftRows operation
 */
void InvShiftRows(uint8_t* state) {
    uint8_t tmp;
    // Row 1: shift right by 1
    tmp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = tmp;
    // Row 2: shift right by 2
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    // Row 3: shift right by 3
    tmp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = tmp;
}

/**
 * XORs the state with the round key (AddRoundKey step)
 */
void AddRoundKey(uint8_t* state, const uint8_t* roundKey) {
    for (int i = 0; i < 16; i++) state[i] ^= roundKey[i];
}

/**
 * Multiplies by x in GF(2^8) (used in MixColumns)
 */
uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1B : 0x00);
}

/**
 * Multiplies two bytes in GF(2^8) (used in MixColumns and InvMixColumns)
 */
uint8_t multiply(uint8_t x, uint8_t y) {
    uint8_t result = 0;
    while (y) {
        if (y & 1) result ^= x;
        x = xtime(x);
        y >>= 1;
    }
    return result;
}

/**
 * MixColumns transformation (column mixing using finite field arithmetic)
 */
void MixColumns(uint8_t* state) {
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

/**
 * Inverse MixColumns transformation (used in decryption)
 */
void InvMixColumns(uint8_t* state) {
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

/**
 * Expands a 256-bit AES key into the full round key schedule.
 * @param key       The original 32-byte (256-bit) key
 * @param roundKeys Output buffer for all round keys (240 bytes for AES-256)
 */
void KeyExpansion256(const uint8_t* key, uint8_t* roundKeys) {
    const uint8_t Rcon[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};
    memcpy(roundKeys, key, 32); // First 8 words are the original key
    uint8_t temp[4];
    int i = 8;
    int rconIdx = 0;
    while (i < 60) {
        for (int j = 0; j < 4; j++)
            temp[j] = roundKeys[(i - 1) * 4 + j];
        if (i % 8 == 0) {
            // Rotate word, apply S-box, and XOR with round constant
            uint8_t t = temp[0];
            temp[0] = sbox[temp[1]] ^ Rcon[rconIdx++];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
        } else if (i % 8 == 4) {
            // Apply S-box to all bytes
            for (int j = 0; j < 4; j++)
                temp[j] = sbox[temp[j]];
        }
        for (int j = 0; j < 4; j++)
            roundKeys[i * 4 + j] = roundKeys[(i - 8) * 4 + j] ^ temp[j];
        i++;
    }
}

/**
 * Encrypts a single 16-byte block using AES-256.
 * @param input     16-byte plaintext block
 * @param output    16-byte ciphertext block (output)
 * @param roundKeys Expanded round keys (240 bytes)
 */
void AES_Encrypt256(const uint8_t* input, uint8_t* output, const uint8_t* roundKeys) {
    memcpy(output, input, 16);           // Copy input to output buffer
    AddRoundKey(output, roundKeys);      // Initial AddRoundKey
    for (int round = 1; round < AES_ROUNDS; round++) {
        SubBytes(output);                // Substitute bytes
        ShiftRows(output);               // Shift rows
        MixColumns(output);              // Mix columns
        AddRoundKey(output, roundKeys + round * 16); // Add round key
    }
    SubBytes(output);                    // Final round (no MixColumns)
    ShiftRows(output);
    AddRoundKey(output, roundKeys + AES_ROUNDS * 16);
}

/**
 * Decrypts a single 16-byte block using AES-256.
 * @param input     16-byte ciphertext block
 * @param output    16-byte plaintext block (output)
 * @param roundKeys Expanded round keys (240 bytes)
 */
void AES_Decrypt256(const uint8_t* input, uint8_t* output, const uint8_t* roundKeys) {
    memcpy(output, input, 16);           // Copy input to output buffer
    AddRoundKey(output, roundKeys + AES_ROUNDS * 16); // Initial AddRoundKey (last round key)
    for (int round = AES_ROUNDS - 1; round > 0; round--) {
        InvShiftRows(output);            // Inverse shift rows
        InvSubBytes(output);             // Inverse substitute bytes
        AddRoundKey(output, roundKeys + round * 16); // Add round key
        InvMixColumns(output);           // Inverse mix columns
    }
    InvShiftRows(output);                // Final round (no InvMixColumns)
    InvSubBytes(output);
    AddRoundKey(output, roundKeys);      // Add initial round key
}

////////////////////////////////////////////////////////////

int main() {
    // 256-bit AES key (32 bytes)
    uint8_t key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    // Allocate memory for plaintext, ciphertext, and decrypted data
    uint8_t (*plaintext)[16] = new uint8_t[NUM_BLOCKS][16];
    uint8_t (*encrypted)[16] = new uint8_t[NUM_BLOCKS][16];
    uint8_t (*decrypted)[16] = new uint8_t[NUM_BLOCKS][16];
    uint8_t roundKeys[240]; // Buffer for all round keys

    // Generate random plaintext blocks
    generatePlaintext(plaintext, NUM_BLOCKS);
    cout << "Generated plaintext of size: " << DATA_SIZE_MB << " MB (" << NUM_BLOCKS << " blocks)\n";

    // Expand the key into round keys
    KeyExpansion256(key, roundKeys);

    // Encrypt all blocks and measure time
    cout << "\n[CPU] AES-256 Batch Encryption: " << NUM_BLOCKS << " blocks\n";
    auto start = high_resolution_clock::now();
    for (int i = 0; i < NUM_BLOCKS; i++) {
        AES_Encrypt256(plaintext[i], encrypted[i], roundKeys);
    }
    auto end = high_resolution_clock::now();
    cout << "[CPU] Encryption Time: " << duration_cast<milliseconds>(end - start).count() << " ms\n";

    // Decrypt all blocks and measure time
    start = high_resolution_clock::now();
    for (int i = 0; i < NUM_BLOCKS; i++) {
        AES_Decrypt256(encrypted[i], decrypted[i], roundKeys);
    }
    end = high_resolution_clock::now();
    cout << "[CPU] Decryption Time: " << duration_cast<milliseconds>(end - start).count() << " ms\n";

    // Verify decryption correctness for the first 5 blocks
    bool allMatch = true;
    for (int i = 0; i < 5; i++) {
        if (memcmp(plaintext[i], decrypted[i], 16) != 0) allMatch = false;
    }

    cout << (allMatch ? "[✓] Decryption verified." : "[✗] Mismatch detected!") << endl;

    // Free allocated memory
    delete[] plaintext;
    delete[] encrypted;
    delete[] decrypted;
    return 0;
}