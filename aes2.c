#include "aes.h"
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stddef.h>

// Table de substitution
const uint8_t sboxtab[256] = {
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
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Variable globale pour le round ciblé
uint8_t targeted_round;

// Constantes de round (Rcon) utilisées dans la génération des clés
const uint8_t rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

// Fonction utilitaire pour afficher l'état actuel de la matrice
void printState(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]) {
    for(int i = 0; i < STATE_ROW_SIZE; i++) {
        for(int j = 0; j < STATE_COL_SIZE; j++) {
            printf("%02x ", state[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}

// Fonction principale d'encryption AES
void AESEncrypt(uint8_t ciphertext[DATA_SIZE], uint8_t plaintext[DATA_SIZE], uint8_t key[DATA_SIZE]) {
    assert(ciphertext != NULL && plaintext != NULL && key != NULL);

    // Déclaration des matrices d'état et des clés
    uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE];        // État courant
    uint8_t roundkeys[ROUND_COUNT + 1][STATE_ROW_SIZE][STATE_COL_SIZE];  // Toutes les clés de round
    uint8_t roundkey[STATE_ROW_SIZE][STATE_COL_SIZE];     // Clé du round courant
    
    // Transformation du message et de la clé en matrices
    MessageToState(state, plaintext);
    MessageToState(roundkey, key);
    printf("État initial:\n");
    printState(state);
    
    // Génération de toutes les clés de round
    KeyGen(roundkeys, roundkey);
    GetRoundKey(roundkey, roundkeys, 0);
    // Premier AddRoundKey avec la clé initiale
    AddRoundKey(state, roundkey);
    printf("Après AddRoundKey initial:\n");
    printState(state);
    
    // Les 10 rounds de l'AES
    for (int round = 1; round <= ROUND_COUNT; round++) {
        printf("\n=== Round %d ===\n", round);
        
        // 1. SubBytes : substitution non-linéaire
        SubBytes(state);
        printf("Après SubBytes:\n");
        printState(state);
        
        // 2. ShiftRows : permutation des lignes
        ShiftRows(state);
        printf("Après ShiftRows:\n");
        printState(state);
        
        // 3. MixColumns : mélange des colonnes (sauf au dernier round)
        if (round != ROUND_COUNT) {
            MixColumns(state);
            printf("Après MixColumns:\n");
            printState(state);
        }
        
        // 4. AddRoundKey : XOR avec la clé de round
        GetRoundKey(roundkey, roundkeys, round);
        AddRoundKey(state, roundkey);
        printf("Après AddRoundKey:\n");
        printState(state);
    }
    
    // Conversion de la matrice finale en message chiffré
    StateToMessage(ciphertext, state);
}

// XOR bit à bit entre l'état et la clé de round
void AddRoundKey(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE], 
                uint8_t roundkey[STATE_ROW_SIZE][STATE_COL_SIZE]) {
    for (int i = 0; i < STATE_ROW_SIZE; i++) {
        for (int j = 0; j < STATE_COL_SIZE; j++) {
            state[i][j] ^= roundkey[i][j];  // XOR (^) entre chaque octet
        }
    }
}

// Substitution de chaque octet en utilisant la S-box
void SubBytes(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]) {
    for (int i = 0; i < STATE_ROW_SIZE; i++) {
        for (int j = 0; j < STATE_COL_SIZE; j++) {
            state[i][j] = sboxtab[state[i][j]];  // Remplacement par la valeur dans la S-box
        }
    }
}

// Décalage cyclique des lignes vers la gauche
void ShiftRows(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]) {
    uint8_t temp;
    
    // Ligne 1 : décalage de 1 position
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;
    
    // Ligne 2 : décalage de 2 positions (swap)
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
    
    // Ligne 3 : décalage de 3 positions
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

// Multiplication dans GF(2^8)
uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t hi_bit_set;
    
    for (int i = 0; i < 8; i++) {
        // Si le bit le plus à droite de b est 1, XOR avec a
        if (b & 1) {
            p ^= a;
        }
        // Sauvegarde du bit de poids fort de a
        hi_bit_set = (a & 0x80);
        // Décalage à gauche de a
        a <<= 1;
        // Si le bit de poids fort était 1, on fait un XOR avec le polynôme irréductible
        if (hi_bit_set) {
            a ^= 0x1B;  // x^8 + x^4 + x^3 + x + 1
        }
        // Décalage à droite de b
        b >>= 1;
    }
    return p;
}

// Mélange des colonnes de la matrice d'état
void MixColumns(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]) {
    uint8_t column[4];
    
    // Traitement de chaque colonne
    for (int j = 0; j < STATE_COL_SIZE; j++) {
        // Copie de la colonne
        for (int i = 0; i < STATE_ROW_SIZE; i++) {
            column[i] = state[i][j];
        }
        // Multiplication de la colonne par la matrice MixColumns
        MCMatrixColumnProduct(column);
        // Mise à jour de la colonne dans l'état
        for (int i = 0; i < STATE_ROW_SIZE; i++) {
            state[i][j] = column[i];
        }
    }
}

// Multiplication d'une colonne par la matrice MixColumns
void MCMatrixColumnProduct(uint8_t column[STATE_COL_SIZE]) {
    uint8_t temp[4];
    // Sauvegarde de la colonne originale
    for (int i = 0; i < 4; i++) {
        temp[i] = column[i];
    }
    
    // Multiplication matricielle dans GF(2^8)
    column[0] = gmul(0x02, temp[0]) ^ gmul(0x03, temp[1]) ^ temp[2] ^ temp[3];
    column[1] = temp[0] ^ gmul(0x02, temp[1]) ^ gmul(0x03, temp[2]) ^ temp[3];
    column[2] = temp[0] ^ temp[1] ^ gmul(0x02, temp[2]) ^ gmul(0x03, temp[3]);
    column[3] = gmul(0x03, temp[0]) ^ temp[1] ^ temp[2] ^ gmul(0x02, temp[3]);
}

// Conversion message -> matrice d'état (column-major order)
void MessageToState(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t message[DATA_SIZE]) {
    for (int i = 0; i < STATE_ROW_SIZE; i++) {
        for (int j = 0; j < STATE_COL_SIZE; j++) {
            state[i][j] = message[i + 4*j];  // Remplissage par colonnes
        }
    }
}

// Conversion matrice d'état -> message (column-major order)
void StateToMessage(uint8_t message[DATA_SIZE], uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]) {
    for (int i = 0; i < STATE_ROW_SIZE; i++) {
        for (int j = 0; j < STATE_COL_SIZE; j++) {
            message[i + 4*j] = state[i][j];  // Lecture par colonnes
        }
    }
}

// Génération de toutes les clés de round
void KeyGen(uint8_t roundkeys[][STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t master_key[STATE_ROW_SIZE][STATE_COL_SIZE]) {
    // Copie de la clé maître comme première clé de round
    for (int i = 0; i < STATE_ROW_SIZE; i++) {
        for (int j = 0; j < STATE_COL_SIZE; j++) {
            roundkeys[0][i][j] = master_key[i][j];
        }
    }
    
    // Génération des clés suivantes
    for (int round = 1; round <= ROUND_COUNT; round++) {
        ColumnFill(roundkeys, round);        // Génère la première colonne
        OtherColumnsFill(roundkeys, round);  // Génère les autres colonnes
    }
}

// Génération de la première colonne d'une clé de round
void ColumnFill(uint8_t roundkeys[][STATE_ROW_SIZE][STATE_COL_SIZE], int round) {
    // Applique la fonction g (rotation + SubBytes + XOR avec Rcon)
    roundkeys[round][0][0] = sboxtab[roundkeys[round-1][1][3]] ^ roundkeys[round-1][0][0] ^ rcon[round-1];
    roundkeys[round][1][0] = sboxtab[roundkeys[round-1][2][3]] ^ roundkeys[round-1][1][0];
    roundkeys[round][2][0] = sboxtab[roundkeys[round-1][3][3]] ^ roundkeys[round-1][2][0];
    roundkeys[round][3][0] = sboxtab[roundkeys[round-1][0][3]] ^ roundkeys[round-1][3][0];
}

// Génération des colonnes 1-3 d'une clé de round
void OtherColumnsFill(uint8_t roundkeys[][STATE_ROW_SIZE][STATE_COL_SIZE], int round) {
    for (int j = 1; j < STATE_COL_SIZE; j++) {
        for (int i = 0; i < STATE_ROW_SIZE; i++) {
            // XOR entre la colonne précédente de la clé courante et la même colonne de la clé précédente
            roundkeys[round][i][j] = roundkeys[round][i][j-1] ^ roundkeys[round-1][i][j];
        }
    }
}

// Récupération d'une clé de round spécifique
void GetRoundKey(uint8_t roundkey[STATE_ROW_SIZE][STATE_COL_SIZE],
                uint8_t roundkeys[][STATE_ROW_SIZE][STATE_COL_SIZE],
                int round) {
    for (int i = 0; i < STATE_ROW_SIZE; i++) {
        for (int j = 0; j < STATE_COL_SIZE; j++) {
            roundkey[i][j] = roundkeys[round][i][j];
        }
    }
}

int main() {
    // Vecteur de test standard NIST pour AES-128
    uint8_t plaintext[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

    uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
                       
    uint8_t ciphertext[16];

    // Affichage du message original en hexadécimal
    printf("Message original: ");
    for(int i = 0; i < 16; i++) {
        printf("%02x ", plaintext[i]);
    }
    printf("\n\n");

    // Chiffrement
    AESEncrypt(ciphertext, plaintext, key);

    // Affichage du message chiffré en hexadécimal
    printf("\nMessage chiffré: ");
    for(int i = 0; i < 16; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    return 0;
}