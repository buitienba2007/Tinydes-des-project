
#ifndef BITS_H
#define BITS_H

#include "cipher.h"

/*Lấy từng bit từ trái qua phải của val ở vị trí pos ,  độ dài width*/
static inline int get_bit(uint64_t value, int position, int width)
{
    return (value >> (width - 1 - position)) & 1;
}

/*Hàm hoán vị dựa theo table ở cypher.h  */
static inline uint64_t permute(uint64_t value, int input_width, const int* table, int output_width)
{
    uint64_t result = 0;
    for (int i = 0; i < output_width; i++) {
        int bit = get_bit(value, table[i], input_width); /*hoán đổi vị trí của value theo vị trí của table[i]*/
        result = (result << 1) | bit;
    }
    return result;
}

/*Dịch vòng trái*/
static inline uint32_t rotate_left(uint32_t value, int shift, int width)
{
     uint32_t result = 0;
    for (int i = 0; i < width; i++) {
        int bit = get_bit(value, (i + shift) % width, width);      
        result = (result << 1) | bit;
    }
    return result;
}

/*Hàm tra cứu Sbox */
static inline uint8_t sbox_lookup(int box_index, uint8_t six_bits)
{
    /*lấy bit ở các vịt trí */
    int bit0 = get_bit(six_bits, 0, 6);
    int bit1 = get_bit(six_bits, 1, 6);
    int bit2 = get_bit(six_bits, 2, 6);
    int bit3 = get_bit(six_bits, 3, 6);
    int bit4 = get_bit(six_bits, 4, 6);
    int bit5 = get_bit(six_bits, 5, 6);

    int row = bit0 * 2 + bit5;                           /*tính chỉ số hàng*/
    int column = bit1 * 8 + bit2 * 4 + bit3 * 2 + bit4;  /*tính chỉ số cột */   
    return SBOX[box_index][row][column];
}

#endif 