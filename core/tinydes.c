#include "cipher.h"
#include "bits.h"

/* Hàm F(R, K) = P-box(S-box(Expand(R) XOR K))
 right: 4 bit, subkey: 6 bit, kết quả: 4 bit
 giá trị trung gian được ghi vào round_trace để hiển thị. */
static uint8_t tinydes_feistel(uint8_t right, uint8_t subkey, TDRound* round_trace)
{
    uint8_t expanded    = permute(right, 4, TD_E, 6);        /* 4 bit -> 6 bit */
    uint8_t xored       = expanded ^ subkey;                  /* XOR với khóa con */
    uint8_t substituted = sbox_lookup(0, xored);             /* box S1: 6 bit -> 4 bit */
    uint8_t output      = permute(substituted, 4, TD_P, 4);   /* P box: hoán vị 4 bit */

    round_trace->E   = expanded;
    round_trace->XOR = xored;
    round_trace->S   = substituted;
    round_trace->F   = output;
    return output;
}
/* Mã hóa (decrypt = 0), giải mã (decrypt = 1) một khối 8 bit
 * trace:  ghi  bước trung gian. Nếu không cần, truyền NULL */

EXPORT uint8_t td_run(uint8_t input, uint8_t key, int decrypt, TDTrace* trace)
{
    TDTrace unused_trace;
    if (trace == NULL) trace = &unused_trace;
/*  Bước 1: sinh 3 khóa con 
     * Tách khóa thành 2 nửa 4 bit, mỗi vòng dịch vòng trái 2 nửa (1, 2, 1 ),
     * nén 8 bit KL KR thành 6 bit theo thứ tự 513270*/
    uint8_t key_left  = key >> 4;       /* KL0*/    
    uint8_t key_right = key & 0xF;      /*LR0 */    
    trace->K = key;
    trace->KL0 = key_left;
    trace->KR0 = key_right;

    uint8_t key_lefts[3];                  /* KL1, KL2, KL3 */    
    uint8_t key_rights[3];                 /* KR1, KR2, KR3 */
    uint8_t subkeys[3];                    /* K1, K2, K3 */
    for (int round = 0; round < 3; round++) {
        key_left  = rotate_left(key_left,  TD_SHIFT[round], 4);
        key_right = rotate_left(key_right, TD_SHIFT[round], 4);
        key_lefts[round]  = key_left;
        key_rights[round] = key_right;
        subkeys[round] = permute((key_left << 4) | key_right, 8, TD_PC2, 6);
    }
/*  Bước 2: tách khối đầu vào thành 2 nửa 4 bit */
    uint8_t left  = input >> 4;
    uint8_t right = input & 0xF;
    trace->in = input;
    trace->L0 = left;
    trace->R0 = right;

    /* Bước 3: 3 vòng Feistel 
     * Mã hóa dùng K1, K2, K3:  L_i = R_(i-1), 
     R_i = L_(i-1) XOR F(R_(i-1), K_i)
     * Giải mã dùng K3, K2, K1: R_(i-1) = L_i, 
     L_(i-1) = R_i XOR F(L_i, K_i) */
    for (int round = 0; round < 3; round++) {
        int key_index;
        if (decrypt == 0) key_index = round;   /*0,1,2*/    
        else                      
        key_index = 2 - round;                 /*2,1,0*/

        TDRound* round_trace = &trace->r[round];
        round_trace->KL = key_lefts[key_index];
        round_trace->KR = key_rights[key_index];
        round_trace->Ki = subkeys[key_index];
        round_trace->L0 = left;
        round_trace->R0 = right;

        uint8_t new_left, new_right;
        if (decrypt == 0) {
            new_left  = right;
            new_right = left ^ tinydes_feistel(right, subkeys[key_index], round_trace);
        } else {
            new_right = left;
            new_left  = right ^ tinydes_feistel(left, subkeys[key_index], round_trace);
        }
        left  = new_left;
        right = new_right;

        round_trace->L1 = left;
        round_trace->R1 = right;
    }
 /*Bước 4: ghép 2 nửa */
    uint8_t output = (left << 4) | right;
    trace->out = output;
    return output;
}
