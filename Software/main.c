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
//  1. Use a struct to carry all the information besides the message
//     and chunks array, that way we can condense the information
//     better.
//  2. Is there a way to make the padding section smaller? Looking at
//     some code on line implementing SHA-1 in C shows a lot less code
//     for that.
//  3. Look into using some of the Intel Intrinsic functions.
//  4. Optimize the SHA_Iteration function to better use the boolean
//     expressions.
//
//********************************************************************

//********************************************************************
//	Pre-processing
//********************************************************************

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//********************************************************************
//	Function Prototypes
//********************************************************************

void SHA1(char* message, uint32_t hash_buffer[5], uint32_t message_size);
void prepMessage(char* message, uint32_t chunks[][16], uint64_t message_size_bits, uint32_t numChunks, uint32_t leftOverBits, uint8_t addChunk);
void shaIteration(uint32_t hash_buffer[5], uint32_t chunk[16]);
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
    uint32_t hash_buffer[5];

    // Call SHA1 algorithm
    SHA1(message, hash_buffer, fsize);

    printf("\n\nMessage: %s\n", message);
    printSHA(hash_buffer);

    //End program
    fclose(fp);
    free(message);
    return 0;
}

//********************************************************************
//	Function Definitions
//********************************************************************

void SHA1(char* message, uint32_t hash_buffer[5], uint32_t message_size)
{
    // Initial values for the hash_buffer
    hash_buffer[0] = 0x67452301;  // h0
    hash_buffer[1] = 0xEFCDAB89;  // h1
    hash_buffer[2] = 0x98BADCFE;  // h2
    hash_buffer[3] = 0x10325476;  // h3
    hash_buffer[4] = 0xC3D2E1F0;  // h4

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
        shaIteration(hash_buffer, chunks[i]);
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
            //memcpy(chunks[i], message + ((j*4)+(i*64)), sizeof(uint32_t));
        }
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
                    if(i == 0){
                        //First byte is 0x80
                        chunks[numChunks-1][j] |= (0x80 << offset);
                    }
                    else
                    {
                        chunks[numChunks-1][j] &= (0x00 << offset);
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

                for(i = 0; i < numBytesPadding; i++){
                    if(i == 0){
                        //First byte is 0x80
                        chunks[numChunks-2][j] |= (0x80 << offset);
                    }
                    else
                    {
                        chunks[numChunks-2][j] &= (0x00 << offset);
                    }

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

void shaIteration(uint32_t hash_buffer[5], uint32_t chunk[16])
{
    // Array to store the extended value
    uint32_t w[80];

    // Iterator variable
    uint16_t i;

    // Values for computation during the iteration
    uint32_t a, b, c, d, e, f, k, temp;

    // Break chunk into 16 32-bit words
    for(i = 0; i < 16; ++i)
    {
        w[i] = chunk[i];
    }

    // Extend the 16 32-bit words into 80 32-bit words
    for(i = 16; i < 80; ++i)
    {
        // Rotate to the left by one
        w[i] = rotl((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1);
    }

    // Initialize hash value for this chunk
    a = hash_buffer[0];
    b = hash_buffer[1];
    c = hash_buffer[2];
    d = hash_buffer[3];
    e = hash_buffer[4];

    // Main Loop
    for(i = 0; i < 80; ++i)
    {
        // Get the k and f value depending on which iteration we are on
        if(i >= 0 && i <= 19)
        {
            f = (b & c) | (~b & d);
            k = 0x5A827999;
        }
        else if( i >= 20 && i <= 39)
        {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        }
        else if( i >= 40 && i <= 59)
        {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        }
        else if( i >= 60 && i <= 79)
        {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        // Store the values in the correct location
        temp = rotl(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = temp;

    }

    // Put the new values into the hash_buffer
    hash_buffer[0] += a;
    hash_buffer[1] += b;
    hash_buffer[2] += c;
    hash_buffer[3] += d;
    hash_buffer[4] += e;
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
