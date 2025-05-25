#include <iostream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <ctime>

using namespace std;
using namespace std::chrono;

const int Nb = 4;        // AES block size in 32-bit words (128 bits / 4 = 4)
const int Nk = 6;        // AES-192 key length = 192 bits = 6 words
const int Nr = 12;       // AES-192 has 12 rounds

#define DATA_SIZE_MB 100
#define NUM_BLOCKS (DATA_SIZE_MB * 1024 * 1024 / 16)

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

// Round constants for key expansion (Rcon)
uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36
};

// Generate random plaintext blocks for encryption
void generatePlaintext(uint8_t (*plaintext)[16], size_t num_blocks) {
    srand(12345); // fixed seed for reproducibility
    for (size_t i = 0; i < num_blocks; ++i) {
        for (size_t j = 0; j < 16; ++j) {
            plaintext[i][j] = rand() % 256; // Fill each byte with a random value
        }
    }
}

// --- AES Helper Functions ---

// Multiply by x (i.e., {02}) in GF(2^8)
uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1B : 0x00);
}

// General multiplication in GF(2^8)
uint8_t multiply(uint8_t x, uint8_t y) {
    uint8_t result = 0;
    while (y) {
        if (y & 1) result ^= x; // Add x to result if lowest bit of y is set
        x = xtime(x);           // Multiply x by {02}
        y >>= 1;                // Shift y right by 1
    }
    return result;
}

// SubBytes step: substitute each byte in the state with its S-box value
void SubBytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++)
        state[i][j] = sbox[state[i][j]];
}

// InvSubBytes step: substitute each byte in the state with its inverse S-box value
void InvSubBytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++)
        state[i][j] = inv_sbox[state[i][j]];
}

// ShiftRows step: cyclically shift the rows of the state
void ShiftRows(uint8_t state[4][4]) {
    uint8_t temp;

    // Row 1: shift left by 1
    temp = state[1][0];
    for (int i = 0; i < 3; i++) state[1][i] = state[1][i + 1];
    state[1][3] = temp;

    // Row 2: shift left by 2
    temp = state[2][0];
    state[2][0] = state[2][2]; state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3]; state[2][3] = temp;

    // Row 3: shift left by 3 (or right by 1)
    temp = state[3][3];
    for (int i = 3; i > 0; i--) state[3][i] = state[3][i - 1];
    state[3][0] = temp;
}

// InvShiftRows step: cyclically shift the rows of the state in the opposite direction
void InvShiftRows(uint8_t state[4][4]) {
    uint8_t temp;

    // Row 1: shift right by 1
    temp = state[1][3];
    for (int i = 3; i > 0; i--) state[1][i] = state[1][i - 1];
    state[1][0] = temp;

    // Row 2: shift right by 2
    temp = state[2][0];
    state[2][0] = state[2][2]; state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3]; state[2][3] = temp;

    // Row 3: shift right by 3 (or left by 1)
    temp = state[3][0];
    for (int i = 0; i < 3; i++) state[3][i] = state[3][i + 1];
    state[3][3] = temp;
}

// MixColumns step: mix each column of the state
void MixColumns(uint8_t state[4][4]) {
    uint8_t temp[4];
    for (int i = 0; i < 4; i++) {
        temp[0] = multiply(0x02, state[0][i]) ^ multiply(0x03, state[1][i]) ^ state[2][i] ^ state[3][i];
        temp[1] = state[0][i] ^ multiply(0x02, state[1][i]) ^ multiply(0x03, state[2][i]) ^ state[3][i];
        temp[2] = state[0][i] ^ state[1][i] ^ multiply(0x02, state[2][i]) ^ multiply(0x03, state[3][i]);
        temp[3] = multiply(0x03, state[0][i]) ^ state[1][i] ^ state[2][i] ^ multiply(0x02, state[3][i]);
        for (int j = 0; j < 4; j++) state[j][i] = temp[j];
    }
}

// InvMixColumns step: inverse mix each column of the state
void InvMixColumns(uint8_t state[4][4]) {
    uint8_t temp[4];
    for (int i = 0; i < 4; i++) {
        temp[0] = multiply(0x0e, state[0][i]) ^ multiply(0x0b, state[1][i]) ^ multiply(0x0d, state[2][i]) ^ multiply(0x09, state[3][i]);
        temp[1] = multiply(0x09, state[0][i]) ^ multiply(0x0e, state[1][i]) ^ multiply(0x0b, state[2][i]) ^ multiply(0x0d, state[3][i]);
        temp[2] = multiply(0x0d, state[0][i]) ^ multiply(0x09, state[1][i]) ^ multiply(0x0e, state[2][i]) ^ multiply(0x0b, state[3][i]);
        temp[3] = multiply(0x0b, state[0][i]) ^ multiply(0x0d, state[1][i]) ^ multiply(0x09, state[2][i]) ^ multiply(0x0e, state[3][i]);
        for (int j = 0; j < 4; j++) state[j][i] = temp[j];
    }
}

// AddRoundKey step: XOR the state with the round key
void AddRoundKey(uint8_t state[4][4], uint8_t roundKey[16]) {
    for (int i = 0; i < 16; i++) {
        state[i % 4][i / 4] ^= roundKey[i];
    }
}

// Key expansion for AES-192: expands 24-byte key into 208 bytes of round keys
void KeyExpansion192(const uint8_t key[24], uint8_t roundKeys[208]) {
    memcpy(roundKeys, key, 24); // Copy the original key as the first round key
    uint8_t temp[4];
    int i = 24;     // Current position in roundKeys
    int rconIdx = 1; // Rcon index

    while (i < 208) {
        memcpy(temp, &roundKeys[i - 4], 4); // Copy previous 4 bytes

        if (i % 24 == 0) {
            // Rotate, substitute, and XOR with Rcon for every Nk bytes
            uint8_t t = temp[0];
            temp[0] = sbox[temp[1]] ^ Rcon[rconIdx++];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
        }

        // XOR with the word Nk positions earlier
        for (int j = 0; j < 4; j++) {
            roundKeys[i] = roundKeys[i - 24] ^ temp[j];
            i++;
        }
    }
}

// AES-192 block encryption
void AES_Encrypt192(uint8_t input[16], uint8_t output[16], uint8_t roundKeys[208]) {
    uint8_t state[4][4];
    // Copy input block into state array (column-major order)
    for (int i = 0; i < 16; i++) state[i % 4][i / 4] = input[i];
    AddRoundKey(state, roundKeys); // Initial round key addition

    // Nr-1 rounds of SubBytes, ShiftRows, MixColumns, AddRoundKey
    for (int round = 1; round < Nr; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 16);
    }

    // Final round (no MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + Nr * 16);

    // Copy state array back to output block
    for (int i = 0; i < 16; i++) output[i] = state[i % 4][i / 4];
}

// AES-192 block decryption
void AES_Decrypt192(uint8_t input[16], uint8_t output[16], uint8_t roundKeys[208]) {
    uint8_t state[4][4];
    // Copy input block into state array (column-major order)
    for (int i = 0; i < 16; i++) state[i % 4][i / 4] = input[i];
    AddRoundKey(state, roundKeys + Nr * 16); // Initial round key addition (last round key)

    // Nr-1 rounds of InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns
    for (int round = Nr - 1; round > 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + round * 16);
        InvMixColumns(state);
    }

    // Final round (no InvMixColumns)
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys);

    // Copy state array back to output block
    for (int i = 0; i < 16; i++) output[i] = state[i % 4][i / 4];
}

int main() {
    // Example 192-bit AES key
    uint8_t key[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e,
        0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
        0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8,
        0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };

    // Allocate memory for plaintext, encrypted, and decrypted data
    uint8_t (*plaintext)[16] = new uint8_t[NUM_BLOCKS][16];
    uint8_t (*encrypted)[16] = new uint8_t[NUM_BLOCKS][16];
    uint8_t (*decrypted)[16] = new uint8_t[NUM_BLOCKS][16];
    uint8_t roundKeys[208]; // Expanded round keys for AES-192

    // Generate random plaintext data
    generatePlaintext(plaintext, NUM_BLOCKS);
    cout << "Generated plaintext of size: " << DATA_SIZE_MB << " MB (" << NUM_BLOCKS << " blocks)\n";

    // Expand the key into round keys
    KeyExpansion192(key, roundKeys);

    // --- Encryption ---
    cout << "\n[CPU] AES-192 Batch Encryption: " << NUM_BLOCKS << " blocks\n";
    auto start = high_resolution_clock::now();
    for (int i = 0; i < NUM_BLOCKS; i++) {
        AES_Encrypt192(plaintext[i], encrypted[i], roundKeys);
    }
    auto end = high_resolution_clock::now();
    cout << "[CPU] Encryption Time: " << duration_cast<milliseconds>(end - start).count() << " ms\n";

    // --- Decryption ---
    start = high_resolution_clock::now();
    for (int i = 0; i < NUM_BLOCKS; i++) {
        AES_Decrypt192(encrypted[i], decrypted[i], roundKeys);
    }
    end = high_resolution_clock::now();
    cout << "[CPU] Decryption Time: " << duration_cast<milliseconds>(end - start).count() << " ms\n";

    // Verify that decryption matches original plaintext (first 5 blocks)
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