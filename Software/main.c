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
void shaIteration(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e);
void printSHA(void); 

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

    // Initialize the chunks array (+1 for 448 & 64 bits) 
    uint32_t chunks[((message_size_bytes/16) + (message_size_bytes % 16)) + 1][16];

    prepMessage(message, chunks, message_size_bits);
}

void prepMessage(char* message, uint32_t chunks[][16], uint64_t message_size_bits)
{
	//Calculate # of chunks
	uint32_t leftOver = (message_size_bits % 512);
	uint32_t numChunks = (message_size_bits/512) + leftOver;

	uint16_t numBytesPadding = 0;
	uint16_t numWordsPadding = 0;
	
	uint16_t i = 0;
	uint16_t j = 0;

	//Split message into 512 bit chunks
	for(i = 0; i < numChunks; i++){
		for(j = 0; j < 16; j++){
			//chunks[i][j] = message[0*j]<<23 | message[1*j]<<15 | message[2*j]<<7 | message[3*j];
			memcpy(chunks[i], message + (j*4)+(i*64), sizeof(uint32_t)); 
		}
		
	}

	//448 bits = 56 bytes
	//64 bits = 8 bytes

	//Find out how many bits need to be padded to the message to make the size 448 mod 512
	numBytesPadding = (448 - leftOver)/8;

	//First padding begins with 1 then 0's
	//chunks[numChunks+1][0] = 0x80000000;	

	//Fill up remaining padding with 0's
	//for(i = 1; i < numWordsPadding; i++){
	//	chunks[numChunks+1][i] = 0;
	//}

	//Add 64 bit message length to spots chunks[numChunks+1][14] and chunks[numChunks+1][15] 
	//TO DO

}

void shaIteration(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
{

}

void printSHA(void)
{

}
