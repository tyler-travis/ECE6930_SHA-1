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

//********************************************************************
//	Function Prototypes
//********************************************************************

void SHA1(char* message);
void prepMessage(void);
void shaIteration(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e);
void printSHA(void); 

//********************************************************************
//	Main Function
//********************************************************************

int main(int argc, char** argv)
{

	//Initial Buffer Values
	uint32_t h0 = 0x67452301;
	uint32_t h1 = 0xEFCDAB89;
	uint32_t h2 = 0x98BADCFE;
	uint32_t h3 = 0x10325476;
	uint32_t h4 = 0xC3D2E1F0;

	//End program
	return 0;
}

//********************************************************************
//	Function Definitions
//********************************************************************

void prepMessage(void)
{

}

void shaIteration(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
{

}

void printSHA(void)
{

}
