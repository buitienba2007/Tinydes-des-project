#ifndef CIPHER_H
#define CIPHER_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 1. HẰNG SỐ TINYDES */

// Expand 4-bit -> 6-bit
static const int TD_E[6] = {2, 3, 1, 2, 1, 0};

// P-box 4-bit -> 4-bit
static const int TD_P[4] = {2, 0, 3, 1};

// Số bit dịch trái khóa qua 3 vòng
static const int TD_SHIFT[3] = {1, 2, 1};

// Nén khóa Compress 8-bit -> 6-bit
static const int TD_PC2[6] = {5, 1, 3, 2, 7, 0};


/* 2. HẰNG SỐ DES 64-BIT*/

// Hoán vị khởi tạo IP
static const int DES_IP[64] = {
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
    56, 48, 40, 32, 24, 16,  8, 0,
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6
};

// Hoán vị kết thúc FP / IP^-1
static const int DES_FP[64] = {
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25,
    32, 0, 40,  8, 48, 16, 56, 24
};

// Mở rộng R: Expand 32-bit -> 48-bit 
static const int DES_E[48] = {
    31,  0,  1,  2,  3,  4,
     3,  4,  5,  6,  7,  8,
     7,  8,  9, 10, 11, 12,
    11, 12, 13, 14, 15, 16,
    15, 16, 17, 18, 19, 20,
    19, 20, 21, 22, 23, 24,
    23, 24, 25, 26, 27, 28,
    27, 28, 29, 30, 31,  0
};

// Hoán vị P-box 32-bit
static const int DES_P[32] = {
    15,  6, 19, 20, 28, 11, 27, 16,
     0, 14, 22, 25,  4, 17, 30,  9,
     1,  7, 23, 13, 31, 26,  2,  8,
    18, 12, 29,  5, 21, 10,  3, 24
};

// Hoán vị khóa PC-1: 64-bit -> 56-bit 
static const int DES_PC1[56] = {
    56, 48, 40, 32, 24, 16,  8,
     0, 57, 49, 41, 33, 25, 17,
     9,  1, 58, 50, 42, 34, 26,
    18, 10,  2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14,
     6, 61, 53, 45, 37, 29, 21,
    13,  5, 60, 52, 44, 36, 28,
    20, 12,  4, 27, 19, 11,  3
};

// Nén khóa con PC-2: 56-bit -> 48-bit 
static const int DES_PC2[48] = {
    13, 16, 10, 23,  0,  4,
     2, 27, 14,  5, 20,  9,
    22, 18, 11,  3, 25,  7,
    15,  6, 26, 19, 12,  1,
    40, 51, 30, 36, 46, 54,
    29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52,
    45, 41, 49, 35, 28, 31
};

// Số bit dịch trái khóa qua 16 vòng 
static const int DES_SHIFT[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

// 8 hộp S-box (SBOX[0] là S1 dùng chung cho TinyDES và DES)
static const uint8_t SBOX[8][4][16] = {
    // S1
    {
        {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
        { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
        { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
        {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
    },
    // S2
    {
        {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
        { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
        { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
        {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
    },
    // S3
    {
        {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
        {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
        {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
        { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
    },
    // S4
    {
        { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
        {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
        {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
        { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
    },
    // S5
    {
        { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
        {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
        { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
        {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
    },
    // S6
    {
        {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
        {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
        { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
        { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
    },
    // S7
    {
        { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
        {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
        { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
        { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
    },
    // S8
    {
        {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
        { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
        { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
        { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
    }
};


/*3.LƯU KẾT QUẢ TRUNG GIAN */

// 1 vòng của TinyDES
typedef struct {
    uint8_t KL, KR;     // Khóa trái, phải (4-bit)
    uint8_t Ki;         // Khóa con vòng i (6-bit)
    uint8_t L0, R0;     // Nửa trái, phải đầu vòng (4-bit)
    uint8_t E;          // Expand(R0) (6-bit)
    uint8_t XOR;        // E ^ Ki (6-bit)
    uint8_t S;          // S-box(XOR) (4-bit)
    uint8_t F;          // P-box(S) (4-bit)
    uint8_t L1, R1;     // Nửa trái, phải cuối vòng (4-bit)
} TDRound;

// Toàn bộ các bước của TinyDES
typedef struct {
    uint8_t in, K, out; // Khối vào (8-bit), Khóa (8-bit), Khối ra (8-bit)
    uint8_t KL0, KR0;   // 2 nửa khóa ban đầu (4-bit)
    uint8_t L0, R0;     // 2 nửa dữ liệu ban đầu (4-bit)
    TDRound r[3];       // 3 vòng Feistel
} TDTrace;

// 1 vòng của DES 64-bit
typedef struct {
    uint32_t KL, KR;    // Khóa trái, phải (28-bit)
    uint64_t Ki;        // Khóa con vòng i (48-bit)
    uint32_t L0, R0;    // Nửa trái, phải đầu vòng (32-bit)
    uint64_t E;         // Expand(R0) (48-bit)
    uint64_t XOR;       // E ^ Ki (48-bit)
    uint8_t  S_box[8];  // Kết quả 8 hộp S1..S8 (mỗi hộp 4-bit)
    uint32_t S;         // Kết quả gộp 8 hộp S (32-bit)
    uint32_t F;         // P-box(S) (32-bit)
    uint32_t L1, R1;    // Nửa trái, phải cuối vòng (32-bit)
} DESRound;

// Toàn bộ các bước của DES 64-bit
typedef struct {
    uint64_t in, K, out;// Khối vào, Khóa, Khối ra (64-bit)
    uint64_t PC1;       // Khóa sau hoán vị PC-1 (56-bit)
    uint32_t KL0, KR0;  // 2 nửa khóa ban đầu (28-bit)
    uint64_t IP;        // Khối vào sau hoán vị IP (64-bit)
    uint32_t L0, R0;    // 2 nửa dữ liệu sau IP (32-bit)
    DESRound r[16];     // 16 vòng Feistel
    uint64_t swap;      // Ghép đảo R16 L16 trước khi qua FP (64-bit)
} DESTrace;


/* 
 * 4. CÁC HÀM API CHÍNH (Gọi trực tiếp từ C hoặc Python ctypes)
 dec = 0 (Mã hóa), dec = 1 (Giải mã)*/

// Hàm lõi chạy thuật toán và ghi lại từng bước vào struct t (truyền NULL nếu không cần)
EXPORT uint8_t  td_run(uint8_t in, uint8_t K, int dec, TDTrace* t);
EXPORT uint64_t des_run(uint64_t in, uint64_t K, int dec, DESTrace* t);

// Hàm mã hóa/giải mã mảng byte (dùng PKCS#7 padding) để demo mã hóa File/Ảnh
EXPORT int des_buf(const uint8_t* in, int len, const uint8_t* k8, uint8_t* out, int dec);

// Hàm tấn công vét cạn DES rút gọn: N bit hiệu dụng cuối của khóa chưa biết, thử 2^N khóa.
// Trả về số khóa khớp; khóa khớp đầu tiên ghi vào found_key, thứ tự lần thử ghi vào found_index
EXPORT int des_bruteforce(uint64_t plaintext, uint64_t ciphertext, uint64_t known_key, int unknown_bits,
                          uint64_t* found_key, uint64_t* found_index);

#ifdef __cplusplus
}
#endif

#endif