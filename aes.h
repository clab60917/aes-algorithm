#ifndef AES_H
#define AES_H

#include <stdint.h>

// Constantes
#define DATA_SIZE 16
#define STATE_ROW_SIZE 4
#define STATE_COL_SIZE 4
#define ROUND_COUNT 10

// Déclaration de la table S-box
extern const uint8_t sboxtab[256];

// Prototypes des fonctions
void AESEncrypt(uint8_t ciphertext[DATA_SIZE], uint8_t plaintext[DATA_SIZE], uint8_t key[DATA_SIZE]);
void AddRoundKey(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t roundkey[STATE_ROW_SIZE][STATE_COL_SIZE]);
void SubBytes(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]);
void ShiftRows(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]);
void MixColumns(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]);
void MCMatrixColumnProduct(uint8_t column[STATE_COL_SIZE]);
void MessageToState(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t message[DATA_SIZE]);
void StateToMessage(uint8_t message[DATA_SIZE], uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]);
void KeyGen(uint8_t roundkeys[][STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t master_key[STATE_ROW_SIZE][STATE_COL_SIZE]);
void ColumnFill(uint8_t roundkeys[][STATE_ROW_SIZE][STATE_COL_SIZE], int round);
void OtherColumnsFill(uint8_t roundkeys[][STATE_ROW_SIZE][STATE_COL_SIZE], int round);
void GetRoundKey(uint8_t roundkey[STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t roundkeys[][STATE_ROW_SIZE][STATE_COL_SIZE], int round);
uint8_t gmul(uint8_t a, uint8_t b);

#endif
