//********************************************************************
//	Title: SHA-1 Software Implementation (main.cpp)
//	Class: ECE 6760 Hardware Security
//	Author(s): Tyler Travis & Justin Cox
//	Date: 1/19/2016
//********************************************************************

//********************************************************************
//	Pre-processing
//********************************************************************

#include <cstdint>

//********************************************************************
//	Function Prototypes
//********************************************************************

void prepMessage(void);
void shaIteration(unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int e);
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

void shaIteration(unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int e)
{

}

void printSHA(void)
{

}
