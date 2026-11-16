/*  DES 64 bit, 16 vòng Feistel
 Gồm 4 phần:
 -Hàm F
 -Sinh 16 khóa con
 -Mã hóa / giải mã 1 khối 64 bit
 -Mã hóa / giải mã cả tệp (ECB + đệm PKCS#7) và vét cạn DES rút gọn*/
#include "cipher.h"
#include "bits.h"

/* 1. HÀM F */

/* F(R, K) = P(S1..S8(E(R) XOR K))
right: 32 bit, subkey: 48 bit, kết quả: 32 bit */
static uint32_t des_feistel(uint32_t right, uint64_t subkey, DESRound* round_trace)
{
    uint64_t expanded = permute(right, 32, DES_E, 48);     /*  32 bit -> 48 bit */
    uint64_t xored = expanded ^ subkey;                    /* xor với khóa con 48 bit */
   
/* Cắt 48 bit thành 8 nhóm 6 bit vào mỗi hộp S cho ra 4 bit */
uint32_t substituted = 0;
    for (int box = 0; box < 8; box++) {
        uint8_t six_bits = 0;
        for (int j = 0; j < 6; j++)
            six_bits = six_bits * 2 + get_bit(xored, box * 6 + j, 48);

        uint8_t four_bits = sbox_lookup(box, six_bits);    /*mỗi box : 6 bit -> 4 bit*/
        substituted = (substituted << 4) | four_bits;    /*lưu  từng 4 bit vào substituted */
        round_trace->S_box[box] = four_bits;                 
    }

    
    uint32_t output = permute(substituted, 32, DES_P, 32);  /*hoán vị 32 bit*/

    round_trace->E   = expanded;
    round_trace->XOR = xored;
    round_trace->S   = substituted;
    round_trace->F   = output;
    return output;
}
      /*Sinh 16 khóa con */

typedef struct {
    uint64_t after_pc1;          /* khóa sau PC-1 (56 bit) */
    uint32_t left0, right0;      /* C0, D0 (28 bit) */
    uint32_t lefts[16];          /* C1..C16 */
    uint32_t rights[16];         /* D1..D16 */
    uint64_t subkeys[16];        /* K1..K16 (48 bit) */
} DESKeySchedule;

static void des_key_schedule(uint64_t key, DESKeySchedule* schedule)
{
    schedule->after_pc1 = permute(key, 64, DES_PC1, 56);    /* bỏ 8 bit chẵn lẻ */

    uint32_t left  = schedule->after_pc1 >> 28;            /* 28 bit trái */
    uint32_t right = schedule->after_pc1 & 0xFFFFFFF;      /* 28 bit phải (0xFFFFFFF = 28 bit 1) */
    schedule->left0  = left;
    schedule->right0 = right;

    for (int round = 0; round < 16; round++) {
        left  = rotate_left(left,  DES_SHIFT[round], 28);
        right = rotate_left(right, DES_SHIFT[round], 28);
        schedule->lefts[round]  = left;
        schedule->rights[round] = right;

        uint64_t joined = ((uint64_t)left << 28) | right;  /* ghép lại 56 bit */
        schedule->subkeys[round] = permute(joined, 56, DES_PC2, 48); 
    }
}
/*Mã hóa/Giải mã 1 block 64 bit*/

/* IP -> 16 vòng Feistel -> đổi chỗ thành R16 L16 -> FP*/

static uint64_t des_block(uint64_t input, const DESKeySchedule* schedule, int decrypt, DESTrace* trace)
{
    DESTrace unused_trace;
    if (trace == NULL) trace = &unused_trace;

    uint64_t after_ip = permute(input, 64, DES_IP, 64);
    uint32_t left  = after_ip >> 32;           /* 32 bit trái */
    uint32_t right = after_ip & 0xFFFFFFFF;    /* 32 bit phải */
    trace->IP = after_ip;
    trace->L0 = left;
    trace->R0 = right;

    for (int round = 0; round < 16; round++) {
        int key_index;
        if (decrypt == 0) key_index = round;    /* 0->15  = K1->K16 */   
        else              
        key_index = 15 - round;                 /* 15->0  = K16->K1 */

        DESRound* round_trace = &trace->r[round];
        round_trace->KL = schedule->lefts[key_index];
        round_trace->KR = schedule->rights[key_index];
        round_trace->Ki = schedule->subkeys[key_index];
        round_trace->L0 = left;
        round_trace->R0 = right;

        /* L_i = R_(i-1),  R_i = L_(i-1) xor F(R_(i-1), K_i) */
        uint32_t new_left  = right;
        uint32_t new_right = left ^ des_feistel(right, schedule->subkeys[key_index], round_trace);
        left  = new_left;
        right = new_right;

        round_trace->L1 = left;
        round_trace->R1 = right;
    }

    uint64_t swapped = ((uint64_t)right << 32) | left;  /*đổi chỗ L16 cho R16*/
    uint64_t output  = permute(swapped, 64, DES_FP, 64); /*hoán vị FP*/
    trace->swap = swapped;
    trace->out  = output;
    return output;
}
/* Mã hóa (decrypt = 0), giải mã (decrypt = 1) một khối 64 bit
 * trace:  ghi  bước trung gian. Nếu không cần, truyền NULL */
EXPORT uint64_t des_run(uint64_t input, uint64_t key, int decrypt, DESTrace* trace)
{
    DESTrace unused_trace;
    if (trace == NULL) trace = &unused_trace;

    DESKeySchedule schedule;
    des_key_schedule(key, &schedule);

    trace->in  = input;
    trace->K   = key;
    trace->PC1 = schedule.after_pc1;
    trace->KL0 = schedule.left0;
    trace->KR0 = schedule.right0;
    return des_block(input, &schedule, decrypt, trace);
}


static uint64_t bytes_to_block(const uint8_t* bytes)
{
    uint64_t block = 0;
    for (int i = 0; i < 8; i++)
        block = (block << 8) | bytes[i];
    return block;
}

static void block_to_bytes(uint64_t block, uint8_t* bytes)
{
    for (int i = 7; i >= 0; i--) {
        bytes[i] = block & 0xFF;           
        block = block >> 8;
    }
}

/* Mã hóa: thêm đệm PKCS#7 rồi mã hóa từng khối 8 byte.
 * Đệm: thêm n byte, mỗi byte có giá trị n (n từ 1 đến 8).
 * Trả về độ dài bản mã. */
static int des_encrypt_bytes(const uint8_t* input, int length, const DESKeySchedule* schedule, uint8_t* output)
{
    int padding = 8 - length % 8;
    int total_length = length + padding;

    for (int offset = 0; offset < total_length; offset += 8) {
        uint8_t block_bytes[8];
        for (int i = 0; i < 8; i++) {
            int position = offset + i;
            if (position < length) block_bytes[i] = input[position];  
            else                   
            block_bytes[i] = padding;           
        }
        uint64_t encrypted = des_block(bytes_to_block(block_bytes), schedule, 0, NULL);
        block_to_bytes(encrypted, output + offset);
    }
    return total_length;
}

static int des_decrypt_bytes(const uint8_t* input, int length, const DESKeySchedule* schedule, uint8_t* output)
{
    if (length <= 0 || length % 8 != 0) return -1;

    for (int offset = 0; offset < length; offset += 8) {
        uint64_t decrypted = des_block(bytes_to_block(input + offset), schedule, 1, NULL);
        block_to_bytes(decrypted, output + offset);
    }

    int padding = output[length - 1];
    if (padding < 1 || padding > 8) return -1;
    for (int i = 1; i <= padding; i++) {
        if (output[length - i] != padding) return -1;
    }
    return length - padding;
}

/* Hàm gọi từ Python: decrypt = 0 mã hóa, 1 giải mã.
 * output cần ít nhất length + 8 byte. */
EXPORT int des_buf(const uint8_t* input, int length, const uint8_t* key_bytes, uint8_t* output, int decrypt)
{
    DESKeySchedule schedule;
    des_key_schedule(bytes_to_block(key_bytes), &schedule);     /* sinh khóa con 1 lần cho cả tệp */

    if (decrypt == 0) return des_encrypt_bytes(input, length, &schedule, output);
    else              return des_decrypt_bytes(input, length, &schedule, output);
}

/* ================= 4b. VÉT CẠN DES RÚT GỌN =================
 * Kẻ tấn công biết P, C và gần hết khóa, chỉ chưa biết unknown_bits bit hiệu dụng cuối.
 * Mỗi byte khóa có 7 bit hiệu dụng và 1 bit chẵn lẻ (bit thấp nhất, PC-1 bỏ đi),
 * nên chỉ thử các bit hiệu dụng. Trả về số khóa thỏa DES(P, K) = C. */
EXPORT int des_bruteforce(uint64_t plaintext, uint64_t ciphertext, uint64_t known_key, int unknown_bits,
                          uint64_t* found_key, uint64_t* found_index)
{
    if (unknown_bits < 1 || unknown_bits > 56) return -1;

    /* Tìm vị trí (đếm từ phải, bit thấp nhất là 0) của các bit chưa biết, bỏ qua bit chẵn lẻ */
    int positions[56];
    int count = 0;
    int position = 0;
    while (count < unknown_bits) {
        if (position % 8 != 0) {                /* vị trí 0, 8, 16, ... là bit chẵn lẻ */
            positions[count] = position;
            count = count + 1;
        }
        position = position + 1;
    }

    /* Xóa các bit chưa biết khỏi khóa */
    uint64_t base_key = known_key;
    for (int i = 0; i < unknown_bits; i++)
        base_key = base_key & ~(1ULL << positions[i]);

    int found_count = 0;
    uint64_t total = 1ULL << unknown_bits;      /* 2^unknown_bits khả năng */

    for (uint64_t guess = 0; guess < total; guess++) {
        /* Bit thứ i của guess được đặt vào vị trí positions[i] của khóa */
        uint64_t candidate_key = base_key;
        for (int i = 0; i < unknown_bits; i++) {
            if ((guess >> i) & 1)
                candidate_key = candidate_key | (1ULL << positions[i]);
        }

        if (des_run(plaintext, candidate_key, 0, NULL) == ciphertext) {
            if (found_count == 0) {
                *found_key   = candidate_key;
                *found_index = guess + 1;       /* lần thử thứ mấy */
            }
            found_count = found_count + 1;
        }
    }
    return found_count;
}
