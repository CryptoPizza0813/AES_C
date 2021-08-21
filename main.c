#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* 상수 정의 */
#define Nb  4        // AES 블록 크기(word)
#define Nk  4        // AES 키 길이(word)

/* 타입 정의 */
typedef unsigned int WORD;
typedef unsigned char BYTE;

/* 매크로 함수 */
#define HIHEX(x) ( x >> 4 )     // 8bit에서 상위 4bit 값을 구하는 함수
#define LOWHEX(x) ( x & 0x0F)   // 8bit에서 하위 4 bit 값을 구하는 함수
#define BTOW(b0, b1, b2, b3) ( ((WORD)b0 << 24) | ((WORD)b1 << 16) | ((WORD)b2 << 8) | (WORD)b3 )   // BYTE를 WORD로 반환하는 함수

/* 함수 선언 */
void AES_Cipher(BYTE* in, BYTE* out, BYTE* key);            // AES 암호화
void AES_Inverse_Cipher(BYTE* in, BYTE* out, BYTE* key);    // AES 복호화
void SubBytes(BYTE state[][4]);     // SubBytes
void ShiftRows(BYTE state[][4]);    // ShiftRows
void MixColumns(BYTE state[][4]);   // MixColumns
void Inv_SubBytes(BYTE state[][4]);     // Inverse SubBytes
void Inv_ShiftRows(BYTE state[][4]);    // Inverse ShiftRows
void Inv_MixColumns(BYTE state[][4]);   // Inverse MixColumns
void AddRoundKey(BYTE state[][4], WORD*);   // AddRoundKey
void KeyExpansion(BYTE* key, WORD* W);  // AES 키 확장 함수
void CirShiftRows(BYTE* row);   // state의 한 행을 1회 오른쪽으로 순환 시프트
void Inv_CirShiftRows(BYTE* row);    // state의 한 행을 1회 왼쪽으로 순환 시프트
WORD SubWord(WORD W);   // SubWord
WORD RotWord(WORD W);   // RotWord
BYTE x_time(BYTE n, BYTE b);    // GF(256) 상에서 곱셈 연산 함수

/* 전역 변수 */
// 암호화 S box
BYTE S_box[16][16] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

// 복호화 S box
BYTE Inv_S_box[16][16] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

// Rcon 상수
static WORD Rcon[11] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000 };
static int Nr; // 라운드 수

////////////////////////////////////////////////////////////////////////////////////////////////

int main()
{
    int i;
    int msg_len = 0, block_count = 0;
    BYTE p_text[128] = { 0, };
    BYTE key[Nk * 4 + 1] = { 0, };
    BYTE c_text[128] = { 0, };
    BYTE inv_c_text[128] = { 0, };

    // 평문 입력
    printf("* 평문 입력: ");
    gets(p_text);

    // 비밀 키 입력
    printf("* 비밀 키 입력: ");
    scanf("%s", key);

    // 메시지 길이와 블록 수를 계산
    msg_len = (int)strlen((char*)p_text);
    block_count = (msg_len % (Nb * 4)) ? (msg_len / (Nb * 4) + 1) : (msg_len / (Nb * 4));

    // 암호화
    for (i = 0; i < block_count; i++)
        AES_Cipher(&p_text[i * Nb * 4], &c_text[i * Nb * 4], key);  

    // 암호문 출력
    printf("\n* 암호문: ");
    for (i = 0; i < block_count*Nb*4; i++)
        printf("%x", c_text[i]);
    printf("\n");

    // 복호화
    for (i = 0; i < block_count; i++)
        AES_Inverse_Cipher(&c_text[i * Nb * 4], &inv_c_text[i * Nb * 4], key);  

    // 복호문 출력
    printf("\n* 복호문 : ");
    for (i = 0; i < msg_len; i++)
        printf("%c", inv_c_text[i]);
    printf("\n");

    return 0;
}


////////////////////////////////////////////////////////////////////////////////////////////////

// SubBytes 프로그램
void SubBytes(BYTE state[][4])
{
    int i, j;

    // state의 한 바이트 값을 상위 4비트와 하위 4비트로 나누어 각각 S box의 행과 열로 사용
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[i][j] = S_box[HIHEX(state[i][j])][LOWHEX(state[i][j])];


}

// Inverse SubBytes 프로그램
void Inv_SubBytes(BYTE state[][4])
{
    int i, j;

    // state의 한 바이트 값을 상위 4비트와 하위 4비트로 나누어 각각 Inverse S box의 행과 열로 사용
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[i][j] = Inv_S_box[HIHEX(state[i][j])][LOWHEX(state[i][j])];

}

// ShiftRows, CirShiftRows 프로그램
void ShiftRows(BYTE state[][4])
{
    int i, j;

    for (i = 1; i < 4; i++)
        for (j = 0; j < i; j++)
            CirShiftRows(state[i]);
}

void CirShiftRows(BYTE* row)
{
    // state의 한 행을 한번 오른쪽으로 순환 이동
    BYTE temp = row[0];

    row[0] = row[1];
    row[1] = row[2];
    row[2] = row[3];
    row[3] = temp;
}

// Inverse ShiftRows, Inverse CirShiftRows 프로그램
void Inv_ShiftRows(BYTE state[][4])
{
    int i, j;

    for (i = 1; i < 4; i++)
        for (j = 0; j < i; j++)
            Inv_CirShiftRows(state[i]);
} 

void Inv_CirShiftRows(BYTE* row)
{
    // state의 한 행을 한 번 왼쪽으로 순환 이동    
    BYTE temp = row[3];

    row[3] = row[2];
    row[2] = row[1];
    row[1] = row[0];
    row[0] = temp;
}

// MixColumns 프로그램
void MixColumns(BYTE state[][4])
{
    int i, j, k;
    BYTE a[4][4] = {
                    0x02, 0x03, 0x01, 0x01,
                    0x01, 0x02, 0x03, 0x01,
                    0x01, 0x01, 0x02, 0x03,
                    0x03, 0x01, 0x01, 0x02 };

    BYTE b[4][4] = { 0, };

    for (int i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
            for (k = 0; k < 4; k++)
                b[i][j] ^= x_time(a[i][k], state[k][j]);
    }

    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[i][j] = b[i][j];
}

// Inverse MixColumns 프로그램
void Inv_MixColumns(BYTE state[][4])
{
    int i, j, k;
    BYTE a[4][4] = {
                    0x0e, 0x0b, 0x0d, 0x09,
                    0x09, 0x0e, 0x0b, 0x0d,
                    0x0d, 0x09, 0x0e, 0x0b,
                    0x0b, 0x0d, 0x09, 0x0e };

    BYTE b[4][4] = { 0, };

    for (int i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
            for (k = 0; k < 4; k++)
                b[i][j] ^= x_time(a[i][k], state[k][j]);
    }

    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[i][j] = b[i][j];

}

// GF(256) 곱셈 연산 프로그램
BYTE x_time(BYTE b, BYTE n)
{
    int i;
    BYTE temp = 0, mask = 0x01;

    for (i = 0; i < 8; i++)
    {
        if (n & mask)
            temp ^= b;

        if (b & 0x80)
            b = (b << 1) ^ 0x1b;
        else
            b <<= 1;

        mask <<= 1;
    }

    return temp;
}

// AddRoundKey 프로그램
void AddRoundKey(BYTE state[][4], WORD* rKey)
{
    int i, j;
    WORD mask, shift;

    for (i = 0; i < 4; i++)
    {
        shift = 24;
        mask = 0xff000000;

        for (j = 0; j < 4; j++)
        {
            state[j][i] = ((rKey[i] & mask) >> shift) ^ state[j][i];
            mask >>= 8;
            shift -= 8;
        }
    }
}

// KeyExpansion 프로그램
void KeyExpansion(BYTE* key, WORD* W)
{
    WORD temp;
    int i = 0;

    // 128비트의 키를 워드 W[0] ~ W[3]에 저장
    while (i < Nk)
    {
        W[i] = BTOW(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
        i = i + 1;
    }

    i = Nk;

    // 키를 확장하여 W[4]부터 W[Nb*Nr]까지 확장된 키 저장
    while (i < (Nb * (Nr + 1)))
    {
        temp = W[i - 1];  // 이전 워드 값을 임시 워드 temp에 저장
        if (i % Nk == 0)
            temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk - 1];
        else if ((Nk > 6) && (i % Nk == 4))
            temp = SubWord(temp);

        W[i] = W[i - Nk] ^ temp;
        i += 1;
    }
}

// RotWord 프로그램
WORD RotWord(WORD W)
{
    return ((W & 0xff000000) >> 24) | (W << 8);
}

// SubWord 프로그램
WORD SubWord(WORD W)
{
    int i;
    WORD out = 0, mask = 0xff000000;
    BYTE shift = 24;

    for (i = 0; i < 4; i++)
    {
        out += (WORD)S_box[HIHEX((W & mask) >> shift)][LOWHEX((W & mask) >> shift)] << shift;
        mask >>= 8;
        shift -= 8;
    }

    return out;
}

// AES 암호화 프로그램
void AES_Cipher(BYTE* in, BYTE* out, BYTE* key)
{
    int i, j;
    BYTE state[4][4];
    WORD* W;

    if (Nk == 4)
        Nr = 10;
    else if (Nk == 6)
        Nr = 12;
    else if (Nk == 8)
        Nr = 14;

    W = (WORD*)malloc(sizeof(WORD) * Nb * (Nr + 1));

    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[j][i] = in[i * 4 + j];

    KeyExpansion(key, W);

    AddRoundKey(state, W);

    for (i = 0; i < Nr - 1; i++)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, &W[(i + 1) * 4]);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, &W[(i + 1) * 4]);

    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            out[i * 4 + j] = state[j][i];

    free(W);
}

// AES 복호화 프로그램
void AES_Inverse_Cipher(BYTE* in, BYTE* out, BYTE* key)
{
    int i, j;
    BYTE state[4][4];
    WORD* W;

    if (Nk == 4)
        Nr = 10;
    else if (Nk == 6)
        Nr = 12;
    else if (Nk == 8)
        Nr = 14;

    W = (WORD*)malloc(sizeof(WORD) * Nb * (Nr + 1));

    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[j][i] = in[i * 4 + j];

    KeyExpansion(key, W);

    AddRoundKey(state, &W[Nr * Nb]);

    for (i = 0; i < Nr - 1; i++)
    {
        Inv_ShiftRows(state);
        Inv_SubBytes(state);
        AddRoundKey(state, &W[(Nr - i - 1) * Nb]);
        Inv_MixColumns(state);
    }

    Inv_ShiftRows(state);
    Inv_SubBytes(state);
    AddRoundKey(state, &W[(Nr - i - 1) * Nb]);

    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            out[i * 4 + j] = state[j][i];

    free(W);
}

