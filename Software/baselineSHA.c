//********************************************************************
//	Title: SHA-1 Software Implementation (main.cpp)
//	Class: ECE 6760 Hardware Security
//	Author(s): Tyler Travis & Justin Cox
//	Date: 1/19/2016
//********************************************************************

//********************************************************************
//	Some Ideas for future optimization/readability
//********************************************************************
//
//  -  Use a struct to carry all the information besides the message
//     and chunks array, that way we can condense the information
//     better.
//
//  -  Is there a way to make the padding section smaller? Looking at
//     some code on line implementing SHA-1 in C shows a lot less code
//     for that.
//
//  -  Look into using some of the Intel Intrinsic functions.
//
//  -  Optimize the SHA_Iteration function to better use the boolean
//     expressions.
//
//	-  pthreads
//
//	-  Figure out how to do the SHA-1 XOR optimazations
//
//********************************************************************

//********************************************************************
//	Pre-processing
//********************************************************************

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>

//********************************************************************
//  MACROS
//********************************************************************

#define f1(vecB, vecC, vecD) (_mm_or_si128(_mm_and_si128(vecB, vecC), _mm_andnot_si128(vecB, vecD)))
#define f2(vecB, vecC, vecD) (_mm_xor_si128(_mm_xor_si128(vecB, vecC), vecD))
#define f3(vecB, vecC, vecD) (_mm_or_si128(_mm_or_si128(_mm_and_si128(vecB, vecC), _mm_and_si128(vecB, vecD)), _mm_and_si128(vecC, vecD)))
#define f4(vecB, vecC, vecD) (_mm_xor_si128(_mm_xor_si128(vecB, vecC), vecD))

#define temp(vecA, vecE, vecF, k, w1, w2, w3, w4) (_mm_setr_epi32(rotl(((uint32_t*)&vecA)[0],5) + ((uint32_t*)&vecF)[0] + ((uint32_t*)&vecE)[0] + k + w1, \
        rotl(((uint32_t*)&vecA)[1],5) + ((uint32_t*)&vecF)[1] + ((uint32_t*)&vecE)[1] + k + w2, \
        rotl(((uint32_t*)&vecA)[2],5) + ((uint32_t*)&vecF)[2] + ((uint32_t*)&vecE)[2] + k + w3, \
        rotl(((uint32_t*)&vecA)[3],5) + ((uint32_t*)&vecF)[3] + ((uint32_t*)&vecE)[3] + k + w4))

#define setC(vecB) (_mm_setr_epi32(rotl(((uint32_t*)&vecB)[0], 30), rotl(((uint32_t*)&vecB)[1], 30), \
        rotl(((uint32_t*)&vecB)[2], 30), rotl(((uint32_t*)&vecB)[3], 30)))

//********************************************************************
//	Function Prototypes
//********************************************************************

void SHA1(char* message, uint32_t hash_buffer1[5], uint32_t hash_buffer2[5], uint32_t hash_buffer3[5], uint32_t hash_buffer4[5], uint32_t message_size);
void prepMessage(char* message, uint32_t chunks[][16], uint64_t message_size_bits, uint32_t numChunks, uint32_t leftOverBits, uint8_t addChunk);
void shaIteration(uint32_t hash_buffer1[5], uint32_t hash_buffer2[5], uint32_t hash_buffer3[5], uint32_t hash_buffer4[5], uint32_t chunk[16]);
void printSHA(uint32_t hash_buffer[5]);

uint32_t rotl(uint32_t value, uint16_t shift);

//********************************************************************
//	Main Function
//********************************************************************

int main(int argc, char** argv)
{
    // Create file pointer to read in message
    // We will by applying the SHA-1 algorithm to this message
    FILE *fp;
    fp = fopen(argv[1], "r");

    // Determine size of the file
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Allocate the correct memory for the message
    char* message = malloc(fsize);
    fread(message, fsize, 1, fp);

    printf("Input Message: %s\n", message);
    printf("Input Message size: %lu\n\n", fsize);

    // Initialize hash_buffer
    uint32_t hash_buffer1[5];
    uint32_t hash_buffer2[5];
    uint32_t hash_buffer3[5];
    uint32_t hash_buffer4[5];

    // Call SHA1 algorithm
    SHA1(message, hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, fsize);

    printf("\n\nMessage: %s\n", message);
    //**********printSHA(hash_buffer);

    //End program
    fclose(fp);
    free(message);
    return 0;
}

//********************************************************************
//	Function Definitions
//********************************************************************

void SHA1(char* message, uint32_t hash_buffer1[5], uint32_t hash_buffer2[5], uint32_t hash_buffer3[5], uint32_t hash_buffer4[5], uint32_t message_size)
{
    // Initial values for the hash_buffer
    hash_buffer1[0] = 0x67452301;  // h0
    hash_buffer1[1] = 0xEFCDAB89;  // h1
    hash_buffer1[2] = 0x98BADCFE;  // h2
    hash_buffer1[3] = 0x10325476;  // h3
    hash_buffer1[4] = 0xC3D2E1F0;  // h4

    // Get the size of the message
    uint64_t message_size_bytes = message_size;
    uint64_t message_size_bits = message_size_bytes*8;
    uint32_t leftOverBits = message_size_bits % 512;
    uint8_t addChunk = 0;

    if(leftOverBits < 448){
        addChunk = 1;
    }
    else{
        addChunk = 2;
    }

    uint64_t number_of_chunks = (message_size_bytes/64) + addChunk;

    uint16_t i;
    uint16_t j;

    // Initialize the chunks array
    uint32_t chunks[number_of_chunks][16];

    // Prep the message into 512-bit chunks (16 32-bit words)
    prepMessage(message, chunks, message_size_bits, number_of_chunks, leftOverBits, addChunk);

    //################################
    //	FOR DEBUGGING
    //################################
    printf("Message AFTER prep: \n");
    for(i = 0; i < number_of_chunks; i++){
        for(j = 0; j < 16; j++){
            printf("%08X", chunks[i][j]);
        }
    }
    //################################
    //################################

    // This manipulates the bytes as defined by SHA-1
    for(i = 0; i < number_of_chunks; ++i)
    {
        shaIteration(hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, chunks[i]);
    }
}

void prepMessage(char* message, uint32_t chunks[][16], uint64_t message_size_bits, uint32_t numChunks, uint32_t leftOverBits, uint8_t addChunk)
{
    //512 bits = 64 bytes
    //		   = 16 words
    //448 bits = 56 bytes
    //		   = 14 words
    //64 bits = 8 bytes
    //		  = 2 words
    //32 bits = 4 bytes

    uint16_t numBytesPadding = 0;

    uint16_t i = 0;
    uint16_t j = 0;

    uint8_t offset = 24;

    //Split message into 512 bit chunks excluding last chunk
    for(i = 0; i < (numChunks - addChunk); i++){
        for(j = 0; j < 16; j++){
            chunks[i][j] = message[(0*j)+(i*64)]<<24 | message[(1*j)+(i*64)]<<16 | message[(2*j)+(i*64)]<<8 | message[(3*j)+(i*64)];
        }
        //memcpy(chunks[i], message + ((j*4)+(i*64)), sizeof(uint32_t));
    }


    //Fill in last chunk of message bits
    j = 0;
    for(i = 0; i < (leftOverBits/8); i++){
        //Set word to 0x00000000
        if(offset == 24){
            chunks[numChunks-addChunk][j] = 0;
        }

        //Add byte to word in correct position
        chunks[numChunks-addChunk][j] |= (((message[i + ((numChunks-addChunk)*64)]) | 0x00000000) << offset);

        //Reset offset for new word, else decrease offset to next byte position
        if(offset == 0){
            offset = 24;
            j++;
        }
        else{
            offset = offset - 8;
        }

    }

    //--------------------------------
    //	PADDING
    //--------------------------------
    printf("Offset: %d \n", offset);
    printf("Byte number %d \n", j);

    //Different methods for leftOverBits >= 448 and leftOverBits < 448
    switch(addChunk)
    {
        case 1:
            {
                //Calculate bytes of padding
                numBytesPadding = 56 - (leftOverBits/8);
                printf("# padding: %d \n", numBytesPadding);


                for(i = 0; i < numBytesPadding; i++){

                    //Set word to 0x00000000
                    if(offset == 24){
                        chunks[numChunks-addChunk][j] = 0;
                    }

                    if(i == 0){
                        //First byte is 0x80
                        chunks[numChunks-1][j] |= (0x80 << offset);
                    }

                    if(offset == 0){
                        offset = 24;
                        j++;
                    }
                    else{
                        offset = offset - 8;
                    }
                }

                break;

            } //end of case 1
        case 2:
            {
                //Calculate bytes of padding
                numBytesPadding = 64 - (leftOverBits/8);
                printf("# padding: %d \n", numBytesPadding);

                for(i = 0; i < numBytesPadding; i++){

                    //Set word to 0x00000000
                    if(offset == 24){
                        chunks[numChunks-addChunk][j] = 0;
                    }

                    if(i == 0){
                        //First byte is 0x80
                        chunks[numChunks-2][j] |= (0x80 << offset);
                    }

                    //printf("Current word: %08X \n", chunks[numChunks-2][j]);

                    if(offset == 0){
                        offset = 24;
                        j++;
                    }
                    else{
                        offset = offset - 8;
                    }
                }

                //Add 448 bits to last chunk
                for(i = 0; i < 14; i++){
                    chunks[numChunks-1][i] = 0;
                }

                break;

            } //end of case 2
    } //end of switch

    //--------------------------------
    //	APPEND 64-bit message length
    //--------------------------------

    //MSW
    chunks[numChunks-1][14] = message_size_bits >> 32;
    //LSW
    chunks[numChunks-1][15] = message_size_bits & 0x00000000FFFFFFFF;


    //################################
    //	FOR DEBUGGING
    //################################

    //PRINT THE ORIGINAL MESSAGE
    printf("\n");
    printf("The message size in bytes: %d \n", (int)(message_size_bits/8));
    printf("The message size in bits: %d \n", (int)message_size_bits);
    printf("# of leftover bits: %d \n", (int)leftOverBits);


    for(i = 0; i < (message_size_bits/8); i++){
        printf("%c", message[i]);
    }

    //PRINT THE DATA OF ALL THE CHUNKS BY WORDS
    printf("\n\n");
    printf("Number of chunks: %d \n", numChunks);

    for(i = 0; i < numChunks; i++){
        for(j = 0; j < 16; j++){
            printf("%08X", chunks[i][j]);
        }
        printf("\n\n");
    }

    printf("\n\n");

    //################################
    //################################

}

void shaIteration(uint32_t hash_buffer1[5], uint32_t hash_buffer2[5], uint32_t hash_buffer3[5], uint32_t hash_buffer4[5], uint32_t chunk[16])
{
    // Array to store the extended value
    uint32_t w[80];
    uint32_t w1[80];
    uint32_t w2[80];
    uint32_t w3[80];
    uint32_t w4[80];


    // Iterator variable
    uint16_t i;

    // Values for computation during the iteration
    uint32_t a, b, c, d, e, f, k, temp;
    //uint32_t k;

    // Break chunk into 16 32-bit words
    w[0] = chunk[0];
    w[1] = chunk[1];
    w[2] = chunk[2];
    w[3] = chunk[3];
    w[4] = chunk[4];
    w[5] = chunk[5];
    w[6] = chunk[6];
    w[7] = chunk[7];
    w[8] = chunk[8];
    w[9] = chunk[9];
    w[10] = chunk[10];
    w[11] = chunk[11];
    w[12] = chunk[12];
    w[13] = chunk[13];
    w[14] = chunk[14];
    w[15] = chunk[15];

    // Extend the 16 32-bit words into 80 32-bit words
    w[16] = rotl((w[13] ^ w[8] ^ w[2] ^ w[0]), 1);
    w[17] = rotl((w[14] ^ w[9] ^ w[3] ^ w[1]), 1);
    w[18] = rotl((w[15] ^ w[10] ^ w[4] ^ w[2]), 1);
    w[19] = rotl((w[16] ^ w[11] ^ w[5] ^ w[3]), 1);
    w[20] = rotl((w[17] ^ w[12] ^ w[6] ^ w[4]), 1);
    w[21] = rotl((w[18] ^ w[13] ^ w[7] ^ w[5]), 1);
    w[22] = rotl((w[19] ^ w[14] ^ w[8] ^ w[6]), 1);
    w[23] = rotl((w[20] ^ w[15] ^ w[9] ^ w[7]), 1);
    w[24] = rotl((w[21] ^ w[16] ^ w[10] ^ w[8]), 1);
    w[25] = rotl((w[22] ^ w[17] ^ w[11] ^ w[9]), 1);
    w[26] = rotl((w[23] ^ w[18] ^ w[12] ^ w[10]), 1);
    w[27] = rotl((w[24] ^ w[19] ^ w[13] ^ w[11]), 1);
    w[28] = rotl((w[25] ^ w[20] ^ w[14] ^ w[12]), 1);
    w[29] = rotl((w[26] ^ w[21] ^ w[15] ^ w[13]), 1);
    w[30] = rotl((w[27] ^ w[22] ^ w[16] ^ w[14]), 1);
    w[31] = rotl((w[28] ^ w[23] ^ w[17] ^ w[15]), 1);
    w[32] = rotl((w[29] ^ w[24] ^ w[18] ^ w[16]), 1);
    w[33] = rotl((w[30] ^ w[25] ^ w[19] ^ w[17]), 1);
    w[34] = rotl((w[31] ^ w[26] ^ w[20] ^ w[18]), 1);
    w[35] = rotl((w[32] ^ w[27] ^ w[21] ^ w[19]), 1);
    w[36] = rotl((w[33] ^ w[28] ^ w[22] ^ w[20]), 1);
    w[37] = rotl((w[34] ^ w[29] ^ w[23] ^ w[21]), 1);
    w[38] = rotl((w[35] ^ w[30] ^ w[24] ^ w[22]), 1);
    w[39] = rotl((w[36] ^ w[31] ^ w[25] ^ w[23]), 1);
    w[40] = rotl((w[37] ^ w[32] ^ w[26] ^ w[24]), 1);
    w[41] = rotl((w[38] ^ w[33] ^ w[27] ^ w[25]), 1);
    w[42] = rotl((w[39] ^ w[34] ^ w[28] ^ w[26]), 1);
    w[43] = rotl((w[40] ^ w[35] ^ w[29] ^ w[27]), 1);
    w[44] = rotl((w[41] ^ w[36] ^ w[30] ^ w[28]), 1);
    w[45] = rotl((w[42] ^ w[37] ^ w[31] ^ w[29]), 1);
    w[46] = rotl((w[43] ^ w[38] ^ w[32] ^ w[30]), 1);
    w[47] = rotl((w[44] ^ w[39] ^ w[33] ^ w[31]), 1);
    w[48] = rotl((w[45] ^ w[40] ^ w[34] ^ w[32]), 1);
    w[49] = rotl((w[46] ^ w[41] ^ w[35] ^ w[33]), 1);
    w[50] = rotl((w[47] ^ w[42] ^ w[36] ^ w[34]), 1);
    w[51] = rotl((w[48] ^ w[43] ^ w[37] ^ w[35]), 1);
    w[52] = rotl((w[49] ^ w[44] ^ w[38] ^ w[36]), 1);
    w[53] = rotl((w[50] ^ w[45] ^ w[39] ^ w[37]), 1);
    w[54] = rotl((w[51] ^ w[46] ^ w[40] ^ w[38]), 1);
    w[55] = rotl((w[52] ^ w[47] ^ w[41] ^ w[39]), 1);
    w[56] = rotl((w[53] ^ w[48] ^ w[42] ^ w[40]), 1);
    w[57] = rotl((w[54] ^ w[49] ^ w[43] ^ w[41]), 1);
    w[58] = rotl((w[55] ^ w[50] ^ w[44] ^ w[42]), 1);
    w[59] = rotl((w[56] ^ w[51] ^ w[45] ^ w[43]), 1);
    w[60] = rotl((w[57] ^ w[52] ^ w[46] ^ w[44]), 1);
    w[61] = rotl((w[58] ^ w[53] ^ w[47] ^ w[45]), 1);
    w[62] = rotl((w[59] ^ w[54] ^ w[48] ^ w[46]), 1);
    w[63] = rotl((w[60] ^ w[55] ^ w[49] ^ w[47]), 1);
    w[64] = rotl((w[61] ^ w[56] ^ w[50] ^ w[48]), 1);
    w[65] = rotl((w[62] ^ w[57] ^ w[51] ^ w[49]), 1);
    w[66] = rotl((w[63] ^ w[58] ^ w[52] ^ w[50]), 1);
    w[67] = rotl((w[64] ^ w[59] ^ w[53] ^ w[51]), 1);
    w[68] = rotl((w[65] ^ w[60] ^ w[54] ^ w[52]), 1);
    w[69] = rotl((w[66] ^ w[61] ^ w[55] ^ w[53]), 1);
    w[70] = rotl((w[67] ^ w[62] ^ w[56] ^ w[54]), 1);
    w[71] = rotl((w[68] ^ w[63] ^ w[57] ^ w[55]), 1);
    w[72] = rotl((w[69] ^ w[64] ^ w[58] ^ w[56]), 1);
    w[73] = rotl((w[70] ^ w[65] ^ w[59] ^ w[57]), 1);
    w[74] = rotl((w[71] ^ w[66] ^ w[60] ^ w[58]), 1);
    w[75] = rotl((w[72] ^ w[67] ^ w[61] ^ w[59]), 1);
    w[76] = rotl((w[73] ^ w[68] ^ w[62] ^ w[60]), 1);
    w[77] = rotl((w[74] ^ w[69] ^ w[63] ^ w[61]), 1);
    w[78] = rotl((w[75] ^ w[70] ^ w[64] ^ w[62]), 1);
    w[79] = rotl((w[76] ^ w[71] ^ w[65] ^ w[63]), 1);


    // Initialize hash value for this chunk
    //a = hash_buffer[0];
    //b = hash_buffer[1];
    //c = hash_buffer[2];
    //d = hash_buffer[3];
    //e = hash_buffer[4];

    __m128i vecA = _mm_setr_epi32(hash_buffer1[0],hash_buffer2[0],hash_buffer3[0],hash_buffer4[0]);
    __m128i vecB = _mm_setr_epi32(hash_buffer1[1],hash_buffer2[1],hash_buffer3[1],hash_buffer4[1]);
    __m128i vecC = _mm_setr_epi32(hash_buffer1[2],hash_buffer2[2],hash_buffer3[2],hash_buffer4[2]);
    __m128i vecD = _mm_setr_epi32(hash_buffer1[3],hash_buffer2[3],hash_buffer3[3],hash_buffer4[3]);
    __m128i vecE = _mm_setr_epi32(hash_buffer1[4],hash_buffer2[4],hash_buffer3[4],hash_buffer4[4]);

    // Main Loop
    
    //f = (b & c) | (~b & d);
    //k = 0x5A827999;
    //temp = rotl(a, 5) + f + e + k + w[0];
    //e = d;
    //d = c;
    //c = rotl(b, 30);
    //b = a;
    //a = temp;

    k = 0x5A827999;
    __m128i vecF = f1(vecB,vecC,vecD);
    __m128i vecTemp = temp(vecA, vecE, vecF, k, w1[0], w2[0], w3[0], w4[0]); 
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[1], w2[1], w3[1], w4[1]); 
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[1];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[2];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[3];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[4];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[5];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[6];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[7];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[8];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[9];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[10];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[11];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[12];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[13];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[14];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[15];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[16];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[17];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[18];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = (b & c) | (~b & d);
    temp = rotl(a, 5) + f + e + k + w[19];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    // -----------------------------------------

    f = b ^ c ^ d;
    k = 0x6ED9EBA1;
    temp = rotl(a, 5) + f + e + k + w[20];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[21];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[22];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[23];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[24];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[25];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[26];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[27];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[28];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[29];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[30];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[31];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[32];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[33];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[34];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[35];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[36];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[37];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[38];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[39];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    // -----------------------
    
    f = (b & c) | (b & d) | (c & d);
    k = 0x8F1BBCDC;
    temp = rotl(a, 5) + f + e + k + w[40];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[41];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[42];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[43];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[44];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[45];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[46];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[47];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[48];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[49];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[50];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[51];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[52];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[53];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[54];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[55];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[56];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[57];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[58];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
    
    f = (b & c) | (b & d) | (c & d);
    temp = rotl(a, 5) + f + e + k + w[59];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    // ------------------------------------

    f = b ^ c ^ d;
    k = 0xCA62C1D6;
    temp = rotl(a, 5) + f + e + k + w[60];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[61];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[62];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[63];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[64];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[65];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[66];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[67];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[68];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[69];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[70];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[71];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[72];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[73];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[74];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[75];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[76];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[77];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[78];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    f = b ^ c ^ d;
    temp = rotl(a, 5) + f + e + k + w[79];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;

    // -----------------------------

    // Put the new values into the hash_buffer
    hash_buffer1[0] += a;
    hash_buffer1[1] += b;
    hash_buffer1[2] += c;
    hash_buffer1[3] += d;
    hash_buffer1[4] += e;
}

void printSHA(uint32_t hash_buffer[5])
{
    printf("SHA-1: %X%X%X%X%X\n", hash_buffer[0], hash_buffer[1], hash_buffer[2], hash_buffer[3], hash_buffer[4]);
    //printf("SHA-1: %X%X%X%X%X\n", hash_buffer[4], hash_buffer[3], hash_buffer[2], hash_buffer[1], hash_buffer[0]);
}

// Does a rotation to the left on value by shift
uint32_t rotl(uint32_t value, uint16_t shift)
{
    return (value << shift) | (value >> (32 - shift));
}
