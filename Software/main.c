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

//********************************************************************
//	Function Prototypes
//********************************************************************

void SHA1(char* message, uint32_t hash_buffer[5]);
void prepMessage(void);
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

    // Initialize the 
    uint32_t chunks[message_size_bytes/16 + message_size_bytes % 16][16];

    prepMessage(message, chunks, message_size_bits);
}

void prepMessage(void)
{

}

void shaIteration(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
{

}

void printSHA(void)
{

}
