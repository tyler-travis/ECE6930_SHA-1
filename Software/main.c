//********************************************************************
//	Title: SHA-1 Software Implementation (main.cpp)
//	Class: ECE 6760 Hardware Security
//	Author(s): Tyler Travis & Justin Cox
//	Date: 1/19/2016
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

void SHA1(char* message, uint32_t hash_buffer[5]);
void prepMessage(char* message, uint32_t chunks[][16], uint64_t message_size_bits);
void shaIteration(uint32_t hash_buffer[5], uint32_t chunk[16]);
void printSHA(void); 

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

    // Initialize hash_buffer
    uint32_t hash_buffer[5];

    // Call SHA1 algorithm
    SHA1(message, hash_buffer);

	//End program
    fclose(fp);
    free(message);
	return 0;
}

//********************************************************************
//	Function Definitions
//********************************************************************

void SHA1(char* message, uint32_t hash_buffer[5])
{
    // Initial values for the hash_buffer
    hash_buffer[0] = 0x67452301;  // h0
    hash_buffer[1] = 0xEFCDAB89;  // h1
    hash_buffer[2] = 0x98BADCFE;  // h2
    hash_buffer[3] = 0x10325476;  // h3
    hash_buffer[4] = 0xC3D2E1F0;  // h4

    // Get the size of the message
    uint64_t message_size_bytes = sizeof(message);
    uint64_t message_size_bits = message_size_bytes*8;
    uint64_t number_of_chunks = (message_size_bytes/16) + (message_size_bytes % 16) + 1;
    
    uint16_t i;

    // Initialize the chunks array (+1 for 448 & 64 bits) 
    uint32_t chunks[number_of_chunks][16];

    // Prep the message into 512-bit chunks (16 32-bit words)
    prepMessage(message, chunks, message_size_bits);

    // This manipulates the bytes as defined by SHA-1
    for(i = 0; i < number_of_chunks; ++i)
    {
        shaIteration(hash_buffer, chunks[i]);
    }
}

void prepMessage(char* message, uint32_t chunks[][16], uint64_t message_size_bits)
{
	//Calculate # of chunks
	uint32_t leftOver = (message_size_bits % 512);
	uint32_t numChunks = (message_size_bits/512) + leftOver;

	uint16_t numPadding = 0;
	
	uint16_t i = 0;
	uint16_t j = 0;

	//Split message into 512 bit chunks
	for(i = 0; i < numChunks; i++){
		for(j = 0; j < 16; j++){
			//chunks[i][j] = message[0*j]<<23 | message[1*j]<<15 | message[2*j]<<7 | message[3*j];
			memcpy(chunks[i], message + (j*4)+(i*64), sizeof(uint32_t)); 
		}
		
	}

	//Find out how many bits need to be padded to the message to make the size 448 mod 512
	numPadding = (448 - leftOver)/32;

	//First padding begins with 1 then 0's
	chunks[numChunks+1][0] = 0x80000000;	

	//Fill up remaining words of padding
	for(i = 1; i < numPadding; i++){
		chunks[numChunks+1][i] = 0;
	}

	//Add 64 bit message length to spots chunks[numChunks+1][14] and chunks[numChunks+1][15] 
	//TO DO

}

void shaIteration(uint32_t hash_buffer[5], uint32_t chunk[16])
{
    uint32_t w[80];
    uint16_t i;
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
        // Get the k and f value depending on which index we are on
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

void printSHA(void)
{

}

// Does a rotation to the left on value by shift
uint32_t rotl(uint32_t value, uint16_t shift)
{
    return ((value << shift) | (value >> (32 - shift)));
}
