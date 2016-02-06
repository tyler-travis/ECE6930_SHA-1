//********************************************************************
//	Title: SHA-1 Software Implementation (main.cpp)
//	Class: ECE 6760 Hardware Security
//	Author(s): Tyler Travis & Justin Cox
//	Date: 1/19/2016
//********************************************************************

//********************************************************************
//	Optimization Explained
//********************************************************************
//
//  We will exploit the XOR operation when expanding the 16 word 
//  chunk by 2048 more bits.  Because of XOR properties, we can 
//  preproccess most of 2048 expanded bits
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
#include <time.h>
#include <sys/time.h>

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
//	Define a bool
//********************************************************************

typedef enum {false, true} bool;

//********************************************************************
//	Constants
//********************************************************************

const char character_set[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
    'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };

const char character_set_lower[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
    'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
    'y', 'z' };

#define N 52
#define N_lower 26
#define string_size 10

//********************************************************************
//	Function Prototypes
//********************************************************************

void SHA1(char* message1, char* message2, char* message3, char* message4,
        uint32_t hash_buffer1[5], uint32_t hash_buffer2[5], uint32_t hash_buffer3[5], uint32_t hash_buffer4[5], uint32_t message_size);
void prepMessage(char* message, uint32_t chunks[][16], uint64_t message_size_bytes);
void shaIteration(uint32_t hash_buffer1[5], uint32_t hash_buffer2[5], uint32_t hash_buffer3[5], uint32_t hash_buffer4[5],
        uint32_t chunk1[16], uint32_t chunk2[16], uint32_t chunk3[16], uint32_t chunk4[16]);
void printSHA(uint32_t hash_buffer[5]);
bool SHAcompare(uint32_t hash_buffer[5], uint32_t input_hash[5]);
bool SHAcompareVEC(__m128i vecInput1, __m128i vecResult1, uint32_t vecInput2, uint32_t vecResult2);

uint32_t rotl(uint32_t value, uint16_t shift);

//********************************************************************
//	Main Function
//********************************************************************

int main(int argc, char** argv)
{
    uint32_t input_hash[5];
    printf("argv[1] = %s\n", argv[1]);

    sscanf(argv[1], "%8x%8x%8x%8x%8x", &input_hash[0], &input_hash[1],
            &input_hash[2], &input_hash[3], &input_hash[4]);

    struct timeval start, end;

    gettimeofday(&start, NULL);

    // Initialize hash_buffer
    uint32_t hash_buffer1[5];
    uint32_t hash_buffer2[5];
    uint32_t hash_buffer3[5];
    uint32_t hash_buffer4[5];

    char password1[11];
    char password2[11];
    char password3[11];
    char password4[11];

    uint32_t i,j,k,l,m,n,o,p,q,r,s;

    for(i = 0; i < string_size; ++i)
    {
        // Set the null terminator in the correct location
        //password1[i + 1] = 0x00;
        //password2[i + 1] = 0x00;
        //password3[i + 1] = 0x00;
        //password4[i + 1] = 0x00;
        for(j = 0; (j < N_lower); j++)
        {
            // If this is the first time here,
            if(i == 0)
            {
                password1[0] = character_set_lower[j++];
                password2[0] = character_set_lower[j++];
                password3[0] = character_set_lower[j++];
                password4[0] = character_set_lower[j];
                SHA1(password1, password2, password3, password4,
                        hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 1);
                //printf("password1: %s\n", password1);
                //printSHA(hash_buffer1);
                //printf("password2: %s\n", password2);
                //printSHA(hash_buffer2);
                //printf("password3: %s\n", password3);
                //printSHA(hash_buffer3);
                //printf("password4: %s\n", password4);
                //printSHA(hash_buffer4);


                if(SHAcompare(hash_buffer1, input_hash))
                {
                    printf("Found match!\nPassword: %s\n", password1);
                    printSHA(hash_buffer1);
                    gettimeofday(&end, NULL);
                    printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                - (start.tv_sec * 1000000 + start.tv_usec)));
                    return 0;
                }
                else if(SHAcompare(hash_buffer2, input_hash))
                {
                    printf("Found match!\nPassword: %s\n", password2);
                    printSHA(hash_buffer2);
                    gettimeofday(&end, NULL);
                    printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                - (start.tv_sec * 1000000 + start.tv_usec)));
                    return 0;
                }
                else if(SHAcompare(hash_buffer3, input_hash))
                {
                    printf("Found match!\nPassword: %s\n", password3);
                    printSHA(hash_buffer3);
                    gettimeofday(&end, NULL);
                    printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                - (start.tv_sec * 1000000 + start.tv_usec)));
                    return 0;
                }
                else if(SHAcompare(hash_buffer4, input_hash))
                {
                    printf("Found match!\nPassword: %s\n", password4);
                    printSHA(hash_buffer4);
                    gettimeofday(&end, NULL);
                    printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                - (start.tv_sec * 1000000 + start.tv_usec)));
                    return 0;
                }
            }
            else
            {
                password1[0] = character_set_lower[j];
                password2[0] = character_set_lower[j];
                password3[0] = character_set_lower[j];
                password4[0] = character_set_lower[j];
            }
            for(k = 0; (k < N_lower) && (i >= 1); k++)
            {
                if(i == 1)
                {
                    password1[1] = character_set_lower[k++];
                    password2[1] = character_set_lower[k++];
                    password3[1] = character_set_lower[k++];
                    password4[1] = character_set_lower[k];
                    SHA1(password1, password2, password3, password4,
                            hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 2);
                    if(SHAcompare(hash_buffer1, input_hash))
                    {
                        printf("Found match!\nPassword: %s\n", password1);
                        printSHA(hash_buffer1);
                        gettimeofday(&end, NULL);
                        printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                    - (start.tv_sec * 1000000 + start.tv_usec)));
                        return 0;
                    }
                    else if(SHAcompare(hash_buffer2, input_hash))
                    {
                        printf("Found match!\nPassword: %s\n", password2);
                        printSHA(hash_buffer2);
                        gettimeofday(&end, NULL);
                        printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                    - (start.tv_sec * 1000000 + start.tv_usec)));
                        return 0;
                    }
                    else if(SHAcompare(hash_buffer3, input_hash))
                    {
                        printf("Found match!\nPassword: %s\n", password3);
                        printSHA(hash_buffer3);
                        gettimeofday(&end, NULL);
                        printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                    - (start.tv_sec * 1000000 + start.tv_usec)));
                        return 0;
                    }
                    else if(SHAcompare(hash_buffer4, input_hash))
                    {
                        printf("Found match!\nPassword: %s\n", password4);
                        printSHA(hash_buffer4);
                        gettimeofday(&end, NULL);
                        printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                    - (start.tv_sec * 1000000 + start.tv_usec)));
                        return 0;
                    }
                }
                else
                {
                    password1[1] = character_set_lower[k];
                    password2[1] = character_set_lower[k];
                    password3[1] = character_set_lower[k];
                    password4[1] = character_set_lower[k];
                }

                for(l = 0; (l < N_lower) && (i >= 2); l++)
                {
                    if(i == 2)
                    {
                        password1[2] = character_set_lower[l++];
                        password2[2] = character_set_lower[l++];
                        password3[2] = character_set_lower[l++];
                        password4[2] = character_set_lower[l];
                        SHA1(password1, password2, password3, password4,
                                hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 3);
                        if(SHAcompare(hash_buffer1, input_hash))
                        {
                            printf("Found match!\nPassword: %s\n", password1);
                            printSHA(hash_buffer1);
                            gettimeofday(&end, NULL);
                            printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                        - (start.tv_sec * 1000000 + start.tv_usec)));
                            return 0;
                        }
                        else if(SHAcompare(hash_buffer2, input_hash))
                        {
                            printf("Found match!\nPassword: %s\n", password2);
                            printSHA(hash_buffer2);
                            gettimeofday(&end, NULL);
                            printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                        - (start.tv_sec * 1000000 + start.tv_usec)));
                            return 0;
                        }
                        else if(SHAcompare(hash_buffer3, input_hash))
                        {
                            printf("Found match!\nPassword: %s\n", password3);
                            printSHA(hash_buffer3);
                            gettimeofday(&end, NULL);
                            printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                        - (start.tv_sec * 1000000 + start.tv_usec)));
                            return 0;
                        }
                        else if(SHAcompare(hash_buffer4, input_hash))
                        {
                            printf("Found match!\nPassword: %s\n", password4);
                            printSHA(hash_buffer4);
                            gettimeofday(&end, NULL);
                            printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                        - (start.tv_sec * 1000000 + start.tv_usec)));
                            return 0;
                        }
                    }
                    else
                    {
                        password1[2] = character_set_lower[l];
                        password2[2] = character_set_lower[l];
                        password3[2] = character_set_lower[l];
                        password4[2] = character_set_lower[l];
                    }
                    for(m = 0; (m < N_lower) && (i >= 3); m++)
                    {
                        if(i == 3)
                        {
                            password1[3] = character_set_lower[m++];
                            password2[3] = character_set_lower[m++];
                            password3[3] = character_set_lower[m++];
                            password4[3] = character_set_lower[m];
                            SHA1(password1, password2, password3, password4,
                                    hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 4);
                            if(SHAcompare(hash_buffer1, input_hash))
                            {
                                printf("Found match!\nPassword: %s\n", password1);
                                printSHA(hash_buffer1);
                                gettimeofday(&end, NULL);
                                printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                            - (start.tv_sec * 1000000 + start.tv_usec)));
                                return 0;
                            }
                            else if(SHAcompare(hash_buffer2, input_hash))
                            {
                                printf("Found match!\nPassword: %s\n", password2);
                                printSHA(hash_buffer2);
                                gettimeofday(&end, NULL);
                                printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                            - (start.tv_sec * 1000000 + start.tv_usec)));
                                return 0;
                            }
                            else if(SHAcompare(hash_buffer3, input_hash))
                            {
                                printf("Found match!\nPassword: %s\n", password3);
                                printSHA(hash_buffer3);
                                gettimeofday(&end, NULL);
                                printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                            - (start.tv_sec * 1000000 + start.tv_usec)));
                                return 0;
                            }
                            else if(SHAcompare(hash_buffer4, input_hash))
                            {
                                printf("Found match!\nPassword: %s\n", password4);
                                printSHA(hash_buffer4);
                                gettimeofday(&end, NULL);
                                printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                            - (start.tv_sec * 1000000 + start.tv_usec)));
                                return 0;
                            }
                        }
                        else
                        {
                            password1[3] = character_set_lower[m];
                            password2[3] = character_set_lower[m];
                            password3[3] = character_set_lower[m];
                            password4[3] = character_set_lower[m];
                        }
                        for(n = 0; (n < N_lower) && (i >= 4); n++)
                        {
                            if(i == 4)
                            {
                                password1[4] = character_set_lower[n++];
                                password2[4] = character_set_lower[n++];
                                password3[4] = character_set_lower[n++];
                                password4[4] = character_set_lower[n];
                                SHA1(password1, password2, password3, password4,
                                        hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 5);
                                if(SHAcompare(hash_buffer1, input_hash))
                                {
                                    printf("Found match!\nPassword: %s\n", password1);
                                    printSHA(hash_buffer1);
                                    gettimeofday(&end, NULL);
                                    printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                - (start.tv_sec * 1000000 + start.tv_usec)));
                                    return 0;
                                }
                                else if(SHAcompare(hash_buffer2, input_hash))
                                {
                                    printf("Found match!\nPassword: %s\n", password2);
                                    printSHA(hash_buffer2);
                                    gettimeofday(&end, NULL);
                                    printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                - (start.tv_sec * 1000000 + start.tv_usec)));
                                    return 0;
                                }
                                else if(SHAcompare(hash_buffer3, input_hash))
                                {
                                    printf("Found match!\nPassword: %s\n", password3);
                                    printSHA(hash_buffer3);
                                    gettimeofday(&end, NULL);
                                    printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                - (start.tv_sec * 1000000 + start.tv_usec)));
                                    return 0;
                                }
                                else if(SHAcompare(hash_buffer4, input_hash))
                                {
                                    printf("Found match!\nPassword: %s\n", password4);
                                    printSHA(hash_buffer4);
                                    gettimeofday(&end, NULL);
                                    printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                - (start.tv_sec * 1000000 + start.tv_usec)));
                                    return 0;
                                }
                            }
                            else
                            {
                                password1[4] = character_set_lower[n];
                                password2[4] = character_set_lower[n];
                                password3[4] = character_set_lower[n];
                                password4[4] = character_set_lower[n];
                            }
                            for(o = 0; (o < N_lower) && (i >= 5); o++)
                            {
                                if(i == 5)
                                {
                                    password1[5] = character_set_lower[o++];
                                    password2[5] = character_set_lower[o++];
                                    password3[5] = character_set_lower[o++];
                                    password4[5] = character_set_lower[o];
                                    SHA1(password1, password2, password3, password4,
                                            hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 6);
                                    if(SHAcompare(hash_buffer1, input_hash))
                                    {
                                        printf("Found match!\nPassword: %s\n", password1);
                                        printSHA(hash_buffer1);
                                        gettimeofday(&end, NULL);
                                        printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                    - (start.tv_sec * 1000000 + start.tv_usec)));
                                        return 0;
                                    }
                                    else if(SHAcompare(hash_buffer2, input_hash))
                                    {
                                        printf("Found match!\nPassword: %s\n", password2);
                                        printSHA(hash_buffer2);
                                        gettimeofday(&end, NULL);
                                        printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                    - (start.tv_sec * 1000000 + start.tv_usec)));
                                        return 0;
                                    }
                                    else if(SHAcompare(hash_buffer3, input_hash))
                                    {
                                        printf("Found match!\nPassword: %s\n", password3);
                                        printSHA(hash_buffer3);
                                        gettimeofday(&end, NULL);
                                        printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                    - (start.tv_sec * 1000000 + start.tv_usec)));
                                        return 0;
                                    }
                                    else if(SHAcompare(hash_buffer4, input_hash))
                                    {
                                        printf("Found match!\nPassword: %s\n", password4);
                                        printSHA(hash_buffer4);
                                        gettimeofday(&end, NULL);
                                        printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                    - (start.tv_sec * 1000000 + start.tv_usec)));
                                        return 0;
                                    }
                                }
                                else
                                {
                                    password1[5] = character_set_lower[o];
                                    password2[5] = character_set_lower[o];
                                    password3[5] = character_set_lower[o];
                                    password4[5] = character_set_lower[o];
                                }
                                for(p = 0; (p < N_lower) && (i >= 6); p++)
                                {
                                    if(i == 6)
                                    {
                                        password1[6] = character_set_lower[p++];
                                        password2[6] = character_set_lower[p++];
                                        password3[6] = character_set_lower[p++];
                                        password4[6] = character_set_lower[p];
                                        SHA1(password1, password2, password3, password4,
                                                hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 7);
                                        if(SHAcompare(hash_buffer1, input_hash))
                                        {
                                            printf("Found match!\nPassword: %s\n", password1);
                                            printSHA(hash_buffer1);
                                            gettimeofday(&end, NULL);
                                            printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                        - (start.tv_sec * 1000000 + start.tv_usec)));
                                            return 0;
                                        }
                                        else if(SHAcompare(hash_buffer2, input_hash))
                                        {
                                            printf("Found match!\nPassword: %s\n", password2);
                                            printSHA(hash_buffer2);
                                            gettimeofday(&end, NULL);
                                            printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                        - (start.tv_sec * 1000000 + start.tv_usec)));
                                            return 0;
                                        }
                                        else if(SHAcompare(hash_buffer3, input_hash))
                                        {
                                            printf("Found match!\nPassword: %s\n", password3);
                                            printSHA(hash_buffer3);
                                            gettimeofday(&end, NULL);
                                            printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                        - (start.tv_sec * 1000000 + start.tv_usec)));
                                            return 0;
                                        }
                                        else if(SHAcompare(hash_buffer4, input_hash))
                                        {
                                            printf("Found match!\nPassword: %s\n", password4);
                                            printSHA(hash_buffer4);
                                            gettimeofday(&end, NULL);
                                            printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                        - (start.tv_sec * 1000000 + start.tv_usec)));
                                            return 0;
                                        }
                                    }
                                    else
                                    {
                                        password1[6] = character_set_lower[p];
                                        password2[6] = character_set_lower[p];
                                        password3[6] = character_set_lower[p];
                                        password4[6] = character_set_lower[p];
                                    }
                                    for(q = 0; (q < N_lower) && (i >= 7); q++)
                                    {
                                        if(i == 7)
                                        {
                                            password1[7] = character_set_lower[q++];
                                            password2[7] = character_set_lower[q++];
                                            password3[7] = character_set_lower[q++];
                                            password4[7] = character_set_lower[q];
                                            SHA1(password1, password2, password3, password4,
                                                    hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 8);
                                            if(SHAcompare(hash_buffer1, input_hash))
                                            {
                                                printf("Found match!\nPassword: %s\n", password1);
                                                printSHA(hash_buffer1);
                                                gettimeofday(&end, NULL);
                                                printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                            - (start.tv_sec * 1000000 + start.tv_usec)));
                                                return 0;
                                            }
                                            else if(SHAcompare(hash_buffer2, input_hash))
                                            {
                                                printf("Found match!\nPassword: %s\n", password2);
                                                printSHA(hash_buffer2);
                                                gettimeofday(&end, NULL);
                                                printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                            - (start.tv_sec * 1000000 + start.tv_usec)));
                                                return 0;
                                            }
                                            else if(SHAcompare(hash_buffer3, input_hash))
                                            {
                                                printf("Found match!\nPassword: %s\n", password3);
                                                printSHA(hash_buffer3);
                                                gettimeofday(&end, NULL);
                                                printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                            - (start.tv_sec * 1000000 + start.tv_usec)));
                                                return 0;
                                            }
                                            else if(SHAcompare(hash_buffer4, input_hash))
                                            {
                                                printf("Found match!\nPassword: %s\n", password4);
                                                printSHA(hash_buffer4);
                                                gettimeofday(&end, NULL);
                                                printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                            - (start.tv_sec * 1000000 + start.tv_usec)));
                                                return 0;
                                            }
                                        }
                                        else
                                        {
                                            password1[7] = character_set_lower[q];
                                            password2[7] = character_set_lower[q];
                                            password3[7] = character_set_lower[q];
                                            password4[7] = character_set_lower[q];
                                        }
                                        for(r = 0; (r < N_lower) && (i >= 8); r++)
                                        {
                                            if(i == 8)
                                            {
                                                password1[8] = character_set_lower[r++];
                                                password2[8] = character_set_lower[r++];
                                                password3[8] = character_set_lower[r++];
                                                password4[8] = character_set_lower[r];
                                                SHA1(password1, password2, password3, password4,
                                                        hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 9);
                                                if(SHAcompare(hash_buffer1, input_hash))
                                                {
                                                    printf("Found match!\nPassword: %s\n", password1);
                                                    printSHA(hash_buffer1);
                                                    gettimeofday(&end, NULL);
                                                    printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                                - (start.tv_sec * 1000000 + start.tv_usec)));
                                                    return 0;
                                                }
                                                else if(SHAcompare(hash_buffer2, input_hash))
                                                {
                                                    printf("Found match!\nPassword: %s\n", password2);
                                                    printSHA(hash_buffer2);
                                                    gettimeofday(&end, NULL);
                                                    printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                                - (start.tv_sec * 1000000 + start.tv_usec)));
                                                    return 0;
                                                }
                                                else if(SHAcompare(hash_buffer3, input_hash))
                                                {
                                                    printf("Found match!\nPassword: %s\n", password3);
                                                    printSHA(hash_buffer3);
                                                    gettimeofday(&end, NULL);
                                                    printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                                - (start.tv_sec * 1000000 + start.tv_usec)));
                                                    return 0;
                                                }
                                                else if(SHAcompare(hash_buffer4, input_hash))
                                                {
                                                    printf("Found match!\nPassword: %s\n", password4);
                                                    printSHA(hash_buffer4);
                                                    gettimeofday(&end, NULL);
                                                    printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                                - (start.tv_sec * 1000000 + start.tv_usec)));
                                                    return 0;
                                                }
                                            }
                                            else
                                            {
                                                password1[8] = character_set_lower[r];
                                                password2[8] = character_set_lower[r];
                                                password3[8] = character_set_lower[r];
                                                password4[8] = character_set_lower[r];
                                            }
                                            for(s = 0; (s < N_lower) && (i >= 9); s++)
                                            {
                                                if(i == 9)
                                                {
                                                    password1[9] = character_set_lower[s++];
                                                    password2[9] = character_set_lower[s++];
                                                    password3[9] = character_set_lower[s++];
                                                    password4[9] = character_set_lower[s];
                                                    SHA1(password1, password2, password3, password4,
                                                            hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 10);
                                                    if(SHAcompare(hash_buffer1, input_hash))
                                                    {
                                                        printf("Found match!\nPassword: %s\n", password1);
                                                        printSHA(hash_buffer1);
                                                        gettimeofday(&end, NULL);
                                                        printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                                    - (start.tv_sec * 1000000 + start.tv_usec)));
                                                        return 0;
                                                    }
                                                    else if(SHAcompare(hash_buffer2, input_hash))
                                                    {
                                                        printf("Found match!\nPassword: %s\n", password2);
                                                        printSHA(hash_buffer2);
                                                        gettimeofday(&end, NULL);
                                                        printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                                    - (start.tv_sec * 1000000 + start.tv_usec)));
                                                        return 0;
                                                    }
                                                    else if(SHAcompare(hash_buffer3, input_hash))
                                                    {
                                                        printf("Found match!\nPassword: %s\n", password3);
                                                        printSHA(hash_buffer3);
                                                        gettimeofday(&end, NULL);
                                                        printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                                    - (start.tv_sec * 1000000 + start.tv_usec)));
                                                        return 0;
                                                    }
                                                    else if(SHAcompare(hash_buffer4, input_hash))
                                                    {
                                                        printf("Found match!\nPassword: %s\n", password4);
                                                        printSHA(hash_buffer4);
                                                        gettimeofday(&end, NULL);
                                                        printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                                                                    - (start.tv_sec * 1000000 + start.tv_usec)));
                                                        return 0;
                                                    }
                                                }
                                                else
                                                {
                                                    password1[9] = character_set_lower[s];
                                                    password2[9] = character_set_lower[s];
                                                    password3[9] = character_set_lower[s];
                                                    password4[9] = character_set_lower[s];
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    printf("Unable to find hash: %s\n", argv[1]);

    /*char* message1 = "barfoo";
      char* message2 = "Hello1";
      char* message3 = "World1";
      char* message4 = "foobar";

      uint32_t fsize = 6;

      printf("Input Message: %s\n", message1);
      printf("Input Message size: %d\n\n", fsize);

    // Initialize hash_buffer
    uint32_t hash_buffer1[5];
    uint32_t hash_buffer2[5];
    uint32_t hash_buffer3[5];
    uint32_t hash_buffer4[5];

    // Call SHA1 algorithm
    SHA1(message1, message2, message3, message4,
    hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, fsize);

    printf("\n\nMessage: %s\n", message1);
    printSHA(hash_buffer1);
    printf("\n\nMessage: %s\n", message2);
    printSHA(hash_buffer2);
    printf("\n\nMessage: %s\n", message3);
    printSHA(hash_buffer3);
    printf("\n\nMessage: %s\n", message4);
    printSHA(hash_buffer4);*/

    //End program
    return 0;
}

//********************************************************************
//	Function Definitions
//********************************************************************

void SHA1(char* message1, char* message2, char* message3, char* message4, uint32_t hash_buffer1[5], uint32_t hash_buffer2[5], uint32_t hash_buffer3[5], uint32_t hash_buffer4[5], uint32_t message_size)
{
    // Initial values for the hash_buffer
    hash_buffer1[0] = 0x67452301;  // h0
    hash_buffer1[1] = 0xEFCDAB89;  // h1
    hash_buffer1[2] = 0x98BADCFE;  // h2
    hash_buffer1[3] = 0x10325476;  // h3
    hash_buffer1[4] = 0xC3D2E1F0;  // h4

    // Initial values for the hash_buffer
    hash_buffer2[0] = 0x67452301;  // h0
    hash_buffer2[1] = 0xEFCDAB89;  // h1
    hash_buffer2[2] = 0x98BADCFE;  // h2
    hash_buffer2[3] = 0x10325476;  // h3
    hash_buffer2[4] = 0xC3D2E1F0;  // h4

    // Initial values for the hash_buffer
    hash_buffer3[0] = 0x67452301;  // h0
    hash_buffer3[1] = 0xEFCDAB89;  // h1
    hash_buffer3[2] = 0x98BADCFE;  // h2
    hash_buffer3[3] = 0x10325476;  // h3
    hash_buffer3[4] = 0xC3D2E1F0;  // h4

    // Initial values for the hash_buffer
    hash_buffer4[0] = 0x67452301;  // h0
    hash_buffer4[1] = 0xEFCDAB89;  // h1
    hash_buffer4[2] = 0x98BADCFE;  // h2
    hash_buffer4[3] = 0x10325476;  // h3
    hash_buffer4[4] = 0xC3D2E1F0;  // h4

    // Get the size of the message
    uint64_t message_size_bytes = message_size;

    // Initialize the chunks array
    //***RUNS FASTER AS 2D ARRAY?***
    uint32_t chunks1[1][16];
    uint32_t chunks2[1][16];
    uint32_t chunks3[1][16];
    uint32_t chunks4[1][16];

    // Prep the message into 512-bit chunks (16 32-bit words)
    prepMessage(message1, chunks1, message_size_bytes);
    prepMessage(message2, chunks2, message_size_bytes);
    prepMessage(message3, chunks3, message_size_bytes);
    prepMessage(message4, chunks4, message_size_bytes);


    //Perform Hashing function
    shaIteration(hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, chunks1[0], chunks2[0], chunks3[0], chunks4[0]);

}

void prepMessage(char* message, uint32_t chunks[][16], uint64_t message_size_bytes)
{
    //512 bits = 64 bytes
    //		   = 16 words
    //448 bits = 56 bytes
    //		   = 14 words
    //64 bits = 8 bytes
    //		  = 2 words
    //32 bits = 4 bytes

    //uint16_t i = 0;

    uint64_t message_size_bits = message_size_bytes*8;

    //printf("%s \n", message);

    switch(message_size_bytes){
        case 1:
        {
            //Insert message and padding
            chunks[0][0] = message[0]<<24 | 0x80<<16;
            chunks[0][1] = 0;
            chunks[0][2] = 0;
            chunks[0][3] = 0;
            chunks[0][4] = 0;
            chunks[0][5] = 0;
            chunks[0][6] = 0;
            chunks[0][7] = 0;
            chunks[0][8] = 0;
            chunks[0][9] = 0;
            chunks[0][10] = 0;
            chunks[0][11] = 0;
            chunks[0][12] = 0;
            chunks[0][13] = 0;

            //Append 64-bit size of message
            //MSW
            chunks[0][14] = message_size_bits >> 32;
            //LSW
            chunks[0][15] = message_size_bits & 0x00000000FFFFFFFF;
            break;

        } //end of case 1
        case 2:
        {
            //Insert message and padding
            chunks[0][0] = message[0]<<24 | message[1]<<16 | 0x80<<8;
            chunks[0][1] = 0;
            chunks[0][2] = 0;
            chunks[0][3] = 0;
            chunks[0][4] = 0;
            chunks[0][5] = 0;
            chunks[0][6] = 0;
            chunks[0][7] = 0;
            chunks[0][8] = 0;
            chunks[0][9] = 0;
            chunks[0][10] = 0;
            chunks[0][11] = 0;
            chunks[0][12] = 0;
            chunks[0][13] = 0;

            //Append 64-bit size of message
            //MSW
            chunks[0][14] = message_size_bits >> 32;
            //LSW
            chunks[0][15] = message_size_bits & 0x00000000FFFFFFFF;
            break;
        } //end of case 2
        case 3:
        {
            //Insert message and padding
            chunks[0][0] = message[0]<<24 | message[1]<<16 | message[2]<<8 | 0x80;
            chunks[0][1] = 0;
            chunks[0][2] = 0;
            chunks[0][3] = 0;
            chunks[0][4] = 0;
            chunks[0][5] = 0;
            chunks[0][6] = 0;
            chunks[0][7] = 0;
            chunks[0][8] = 0;
            chunks[0][9] = 0;
            chunks[0][10] = 0;
            chunks[0][11] = 0;
            chunks[0][12] = 0;
            chunks[0][13] = 0;

            //Append 64-bit size of message
            //MSW
            chunks[0][14] = message_size_bits >> 32;
            //LSW
            chunks[0][15] = message_size_bits & 0x00000000FFFFFFFF;
            break;
        } //end of case 3
        case 4:
        {
            //Insert message and padding
            chunks[0][0] = message[0]<<24 | message[1]<<16 | message[2]<<8 | message[3];
            chunks[0][1] = 0x80<<24;
            chunks[0][2] = 0;
            chunks[0][3] = 0;
            chunks[0][4] = 0;
            chunks[0][5] = 0;
            chunks[0][6] = 0;
            chunks[0][7] = 0;
            chunks[0][8] = 0;
            chunks[0][9] = 0;
            chunks[0][10] = 0;
            chunks[0][11] = 0;
            chunks[0][12] = 0;
            chunks[0][13] = 0;

            //Append 64-bit size of message
            //MSW
            chunks[0][14] = message_size_bits >> 32;
            //LSW
            chunks[0][15] = message_size_bits & 0x00000000FFFFFFFF;
            break;
        } //end of case 4
        case 5:
        {
            //Insert message and padding
            chunks[0][0] = message[0]<<24 | message[1]<<16 | message[2]<<8 | message[3];
            chunks[0][1] = message[4]<<24 | 0x80<<16;
            chunks[0][2] = 0;
            chunks[0][3] = 0;
            chunks[0][4] = 0;
            chunks[0][5] = 0;
            chunks[0][6] = 0;
            chunks[0][7] = 0;
            chunks[0][8] = 0;
            chunks[0][9] = 0;
            chunks[0][10] = 0;
            chunks[0][11] = 0;
            chunks[0][12] = 0;
            chunks[0][13] = 0;

            //Append 64-bit size of message
            //MSW
            chunks[0][14] = message_size_bits >> 32;
            //LSW
            chunks[0][15] = message_size_bits & 0x00000000FFFFFFFF;
            break;
        } //end of case 5
        case 6:
        {
            //Insert message and padding
            chunks[0][0] = message[0]<<24 | message[1]<<16 | message[2]<<8 | message[3];
            chunks[0][1] = message[4]<<24 | message[5]<<16 | 0x80<<8;
            chunks[0][2] = 0;
            chunks[0][3] = 0;
            chunks[0][4] = 0;
            chunks[0][5] = 0;
            chunks[0][6] = 0;
            chunks[0][7] = 0;
            chunks[0][8] = 0;
            chunks[0][9] = 0;
            chunks[0][10] = 0;
            chunks[0][11] = 0;
            chunks[0][12] = 0;
            chunks[0][13] = 0;

            //Append 64-bit size of message
            //MSW
            chunks[0][14] = message_size_bits >> 32;
            //LSW
            chunks[0][15] = message_size_bits & 0x00000000FFFFFFFF;
            break;
        } //end of case 6
        case 7:
        {
            //Insert message and padding
            chunks[0][0] = message[0]<<24 | message[1]<<16 | message[2]<<8 | message[3];
            chunks[0][1] = message[4]<<24 | message[5]<<16 | message[6]<<8 | 0x80;
            chunks[0][2] = 0;
            chunks[0][3] = 0;
            chunks[0][4] = 0;
            chunks[0][5] = 0;
            chunks[0][6] = 0;
            chunks[0][7] = 0;
            chunks[0][8] = 0;
            chunks[0][9] = 0;
            chunks[0][10] = 0;
            chunks[0][11] = 0;
            chunks[0][12] = 0;
            chunks[0][13] = 0;

            //Append 64-bit size of message
            //MSW
            chunks[0][14] = message_size_bits >> 32;
            //LSW
            chunks[0][15] = message_size_bits & 0x00000000FFFFFFFF;
            break;
        } //end of case 7
        case 8:
        {
            //Insert message and padding
            chunks[0][0] = message[0]<<24 | message[1]<<16 | message[2]<<8 | message[3];
            chunks[0][1] = message[4]<<24 | message[5]<<16 | message[6]<<8 | message[7];
            chunks[0][2] = 0x80<<24;
            chunks[0][3] = 0;
            chunks[0][4] = 0;
            chunks[0][5] = 0;
            chunks[0][6] = 0;
            chunks[0][7] = 0;
            chunks[0][8] = 0;
            chunks[0][9] = 0;
            chunks[0][10] = 0;
            chunks[0][11] = 0;
            chunks[0][12] = 0;
            chunks[0][13] = 0;

            //Append 64-bit size of message
            //MSW
            chunks[0][14] = message_size_bits >> 32;
            //LSW
            chunks[0][15] = message_size_bits & 0x00000000FFFFFFFF;
            break;
        } //end of case 8
        case 9:
        {
            //Insert message and padding
            chunks[0][0] = message[0]<<24 | message[1]<<16 | message[2]<<8 | message[3];
            chunks[0][1] = message[4]<<24 | message[5]<<16 | message[6]<<8 | message[7];
            chunks[0][2] = message[8]<<24 | 0x80<<16;
            chunks[0][3] = 0;
            chunks[0][4] = 0;
            chunks[0][5] = 0;
            chunks[0][6] = 0;
            chunks[0][7] = 0;
            chunks[0][8] = 0;
            chunks[0][9] = 0;
            chunks[0][10] = 0;
            chunks[0][11] = 0;
            chunks[0][12] = 0;
            chunks[0][13] = 0;

            //Append 64-bit size of message
            //MSW
            chunks[0][14] = message_size_bits >> 32;
            //LSW
            chunks[0][15] = message_size_bits & 0x00000000FFFFFFFF;
            break;
        } //end of case 9
        case 10:
        {
            //Insert message and padding
            chunks[0][0] = message[0]<<24 | message[1]<<16 | message[2]<<8 | message[3];
            chunks[0][1] = message[4]<<24 | message[5]<<16 | message[6]<<8 | message[7];
            chunks[0][2] = message[8]<<24 | message[9]<<16 | 0x80<<8;
            chunks[0][3] = 0;
            chunks[0][4] = 0;
            chunks[0][5] = 0;
            chunks[0][6] = 0;
            chunks[0][7] = 0;
            chunks[0][8] = 0;
            chunks[0][9] = 0;
            chunks[0][10] = 0;
            chunks[0][11] = 0;
            chunks[0][12] = 0;
            chunks[0][13] = 0;

            //Append 64-bit size of message
            //MSW
            chunks[0][14] = message_size_bits >> 32;
            //LSW
            chunks[0][15] = message_size_bits & 0x00000000FFFFFFFF;
            break;
        } //end of case 10
        case 11:
        {
            //Insert message and padding
            chunks[0][0] = message[0]<<24 | message[1]<<16 | message[2]<<8 | message[3];
            chunks[0][1] = message[4]<<24 | message[5]<<16 | message[6]<<8 | message[7];
            chunks[0][2] = message[8]<<24 | message[9]<<16 | message[10]<<8 | 0x80;
            chunks[0][3] = 0;
            chunks[0][4] = 0;
            chunks[0][5] = 0;
            chunks[0][6] = 0;
            chunks[0][7] = 0;
            chunks[0][8] = 0;
            chunks[0][9] = 0;
            chunks[0][10] = 0;
            chunks[0][11] = 0;
            chunks[0][12] = 0;
            chunks[0][13] = 0;

            //Append 64-bit size of message
            //MSW
            chunks[0][14] = message_size_bits >> 32;
            //LSW
            chunks[0][15] = message_size_bits & 0x00000000FFFFFFFF;
            break;
        } //end of case 11
    }//end of switch

}

void shaIteration(uint32_t hash_buffer1[5], uint32_t hash_buffer2[5], uint32_t hash_buffer3[5], uint32_t hash_buffer4[5],
        uint32_t chunk1[16], uint32_t chunk2[16], uint32_t chunk3[16], uint32_t chunk4[16])
{
    // Array to store the extended value
    uint32_t w1[80];
    uint32_t w2[80];
    uint32_t w3[80];
    uint32_t w4[80];


    // Iterator variable
    uint16_t i;

    // Values for computation during the iteration
    uint32_t a, b, c, d, e, f, k, temp;
    //uint32_t k;

    // Break chunk into 16 32-bit words w1
    w1[0] = chunk1[0];
    w1[1] = chunk1[1];
    w1[2] = chunk1[2];
    w1[3] = chunk1[3];
    w1[4] = chunk1[4];
    w1[5] = chunk1[5];
    w1[6] = chunk1[6];
    w1[7] = chunk1[7];
    w1[8] = chunk1[8];
    w1[9] = chunk1[9];
    w1[10] = chunk1[10];
    w1[11] = chunk1[11];
    w1[12] = chunk1[12];
    w1[13] = chunk1[13];
    w1[14] = chunk1[14];
    w1[15] = chunk1[15];

    // Break chunk into 16 32-bit words w2
    w2[0] = chunk2[0];
    w2[1] = chunk2[1];
    w2[2] = chunk2[2];
    w2[3] = chunk2[3];
    w2[4] = chunk2[4];
    w2[5] = chunk2[5];
    w2[6] = chunk2[6];
    w2[7] = chunk2[7];
    w2[8] = chunk2[8];
    w2[9] = chunk2[9];
    w2[10] = chunk2[10];
    w2[11] = chunk2[11];
    w2[12] = chunk2[12];
    w2[13] = chunk2[13];
    w2[14] = chunk2[14];
    w2[15] = chunk2[15];

    // Break chunk into 16 32-bit words w3
    w3[0] = chunk3[0];
    w3[1] = chunk3[1];
    w3[2] = chunk3[2];
    w3[3] = chunk3[3];
    w3[4] = chunk3[4];
    w3[5] = chunk3[5];
    w3[6] = chunk3[6];
    w3[7] = chunk3[7];
    w3[8] = chunk3[8];
    w3[9] = chunk3[9];
    w3[10] = chunk3[10];
    w3[11] = chunk3[11];
    w3[12] = chunk3[12];
    w3[13] = chunk3[13];
    w3[14] = chunk3[14];
    w3[15] = chunk3[15];

    // Break chunk into 16 32-bit words w4
    w4[0] = chunk4[0];
    w4[1] = chunk4[1];
    w4[2] = chunk4[2];
    w4[3] = chunk4[3];
    w4[4] = chunk4[4];
    w4[5] = chunk4[5];
    w4[6] = chunk4[6];
    w4[7] = chunk4[7];
    w4[8] = chunk4[8];
    w4[9] = chunk4[9];
    w4[10] = chunk4[10];
    w4[11] = chunk4[11];
    w4[12] = chunk4[12];
    w4[13] = chunk4[13];
    w4[14] = chunk4[14];
    w4[15] = chunk4[15];

    // Extend the 16 32-bit words into 80 32-bit words w1
    w1[16] = rotl((w1[13] ^ w1[8] ^ w1[2] ^ w1[0]), 1);
    w1[17] = rotl((w1[14] ^ w1[9] ^ w1[3] ^ w1[1]), 1);
    w1[18] = rotl((w1[15] ^ w1[10] ^ w1[4] ^ w1[2]), 1);
    w1[19] = rotl((w1[16] ^ w1[11] ^ w1[5] ^ w1[3]), 1);
    w1[20] = rotl((w1[17] ^ w1[12] ^ w1[6] ^ w1[4]), 1);
    w1[21] = rotl((w1[18] ^ w1[13] ^ w1[7] ^ w1[5]), 1);
    w1[22] = rotl((w1[19] ^ w1[14] ^ w1[8] ^ w1[6]), 1);
    w1[23] = rotl((w1[20] ^ w1[15] ^ w1[9] ^ w1[7]), 1);
    w1[24] = rotl((w1[21] ^ w1[16] ^ w1[10] ^ w1[8]), 1);
    w1[25] = rotl((w1[22] ^ w1[17] ^ w1[11] ^ w1[9]), 1);
    w1[26] = rotl((w1[23] ^ w1[18] ^ w1[12] ^ w1[10]), 1);
    w1[27] = rotl((w1[24] ^ w1[19] ^ w1[13] ^ w1[11]), 1);
    w1[28] = rotl((w1[25] ^ w1[20] ^ w1[14] ^ w1[12]), 1);
    w1[29] = rotl((w1[26] ^ w1[21] ^ w1[15] ^ w1[13]), 1);
    w1[30] = rotl((w1[27] ^ w1[22] ^ w1[16] ^ w1[14]), 1);
    w1[31] = rotl((w1[28] ^ w1[23] ^ w1[17] ^ w1[15]), 1);
    w1[32] = rotl((w1[29] ^ w1[24] ^ w1[18] ^ w1[16]), 1);
    w1[33] = rotl((w1[30] ^ w1[25] ^ w1[19] ^ w1[17]), 1);
    w1[34] = rotl((w1[31] ^ w1[26] ^ w1[20] ^ w1[18]), 1);
    w1[35] = rotl((w1[32] ^ w1[27] ^ w1[21] ^ w1[19]), 1);
    w1[36] = rotl((w1[33] ^ w1[28] ^ w1[22] ^ w1[20]), 1);
    w1[37] = rotl((w1[34] ^ w1[29] ^ w1[23] ^ w1[21]), 1);
    w1[38] = rotl((w1[35] ^ w1[30] ^ w1[24] ^ w1[22]), 1);
    w1[39] = rotl((w1[36] ^ w1[31] ^ w1[25] ^ w1[23]), 1);
    w1[40] = rotl((w1[37] ^ w1[32] ^ w1[26] ^ w1[24]), 1);
    w1[41] = rotl((w1[38] ^ w1[33] ^ w1[27] ^ w1[25]), 1);
    w1[42] = rotl((w1[39] ^ w1[34] ^ w1[28] ^ w1[26]), 1);
    w1[43] = rotl((w1[40] ^ w1[35] ^ w1[29] ^ w1[27]), 1);
    w1[44] = rotl((w1[41] ^ w1[36] ^ w1[30] ^ w1[28]), 1);
    w1[45] = rotl((w1[42] ^ w1[37] ^ w1[31] ^ w1[29]), 1);
    w1[46] = rotl((w1[43] ^ w1[38] ^ w1[32] ^ w1[30]), 1);
    w1[47] = rotl((w1[44] ^ w1[39] ^ w1[33] ^ w1[31]), 1);
    w1[48] = rotl((w1[45] ^ w1[40] ^ w1[34] ^ w1[32]), 1);
    w1[49] = rotl((w1[46] ^ w1[41] ^ w1[35] ^ w1[33]), 1);
    w1[50] = rotl((w1[47] ^ w1[42] ^ w1[36] ^ w1[34]), 1);
    w1[51] = rotl((w1[48] ^ w1[43] ^ w1[37] ^ w1[35]), 1);
    w1[52] = rotl((w1[49] ^ w1[44] ^ w1[38] ^ w1[36]), 1);
    w1[53] = rotl((w1[50] ^ w1[45] ^ w1[39] ^ w1[37]), 1);
    w1[54] = rotl((w1[51] ^ w1[46] ^ w1[40] ^ w1[38]), 1);
    w1[55] = rotl((w1[52] ^ w1[47] ^ w1[41] ^ w1[39]), 1);
    w1[56] = rotl((w1[53] ^ w1[48] ^ w1[42] ^ w1[40]), 1);
    w1[57] = rotl((w1[54] ^ w1[49] ^ w1[43] ^ w1[41]), 1);
    w1[58] = rotl((w1[55] ^ w1[50] ^ w1[44] ^ w1[42]), 1);
    w1[59] = rotl((w1[56] ^ w1[51] ^ w1[45] ^ w1[43]), 1);
    w1[60] = rotl((w1[57] ^ w1[52] ^ w1[46] ^ w1[44]), 1);
    w1[61] = rotl((w1[58] ^ w1[53] ^ w1[47] ^ w1[45]), 1);
    w1[62] = rotl((w1[59] ^ w1[54] ^ w1[48] ^ w1[46]), 1);
    w1[63] = rotl((w1[60] ^ w1[55] ^ w1[49] ^ w1[47]), 1);
    w1[64] = rotl((w1[61] ^ w1[56] ^ w1[50] ^ w1[48]), 1);
    w1[65] = rotl((w1[62] ^ w1[57] ^ w1[51] ^ w1[49]), 1);
    w1[66] = rotl((w1[63] ^ w1[58] ^ w1[52] ^ w1[50]), 1);
    w1[67] = rotl((w1[64] ^ w1[59] ^ w1[53] ^ w1[51]), 1);
    w1[68] = rotl((w1[65] ^ w1[60] ^ w1[54] ^ w1[52]), 1);
    w1[69] = rotl((w1[66] ^ w1[61] ^ w1[55] ^ w1[53]), 1);
    w1[70] = rotl((w1[67] ^ w1[62] ^ w1[56] ^ w1[54]), 1);
    w1[71] = rotl((w1[68] ^ w1[63] ^ w1[57] ^ w1[55]), 1);
    w1[72] = rotl((w1[69] ^ w1[64] ^ w1[58] ^ w1[56]), 1);
    w1[73] = rotl((w1[70] ^ w1[65] ^ w1[59] ^ w1[57]), 1);
    w1[74] = rotl((w1[71] ^ w1[66] ^ w1[60] ^ w1[58]), 1);
    w1[75] = rotl((w1[72] ^ w1[67] ^ w1[61] ^ w1[59]), 1);
    w1[76] = rotl((w1[73] ^ w1[68] ^ w1[62] ^ w1[60]), 1);
    w1[77] = rotl((w1[74] ^ w1[69] ^ w1[63] ^ w1[61]), 1);
    w1[78] = rotl((w1[75] ^ w1[70] ^ w1[64] ^ w1[62]), 1);
    w1[79] = rotl((w1[76] ^ w1[71] ^ w1[65] ^ w1[63]), 1);

    // Extend the 16 32-bit words into 80 32-bit words w2
    w2[16] = rotl((w2[13] ^ w2[8] ^ w2[2] ^ w2[0]), 1);
    w2[17] = rotl((w2[14] ^ w2[9] ^ w2[3] ^ w2[1]), 1);
    w2[18] = rotl((w2[15] ^ w2[10] ^ w2[4] ^ w2[2]), 1);
    w2[19] = rotl((w2[16] ^ w2[11] ^ w2[5] ^ w2[3]), 1);
    w2[20] = rotl((w2[17] ^ w2[12] ^ w2[6] ^ w2[4]), 1);
    w2[21] = rotl((w2[18] ^ w2[13] ^ w2[7] ^ w2[5]), 1);
    w2[22] = rotl((w2[19] ^ w2[14] ^ w2[8] ^ w2[6]), 1);
    w2[23] = rotl((w2[20] ^ w2[15] ^ w2[9] ^ w2[7]), 1);
    w2[24] = rotl((w2[21] ^ w2[16] ^ w2[10] ^ w2[8]), 1);
    w2[25] = rotl((w2[22] ^ w2[17] ^ w2[11] ^ w2[9]), 1);
    w2[26] = rotl((w2[23] ^ w2[18] ^ w2[12] ^ w2[10]), 1);
    w2[27] = rotl((w2[24] ^ w2[19] ^ w2[13] ^ w2[11]), 1);
    w2[28] = rotl((w2[25] ^ w2[20] ^ w2[14] ^ w2[12]), 1);
    w2[29] = rotl((w2[26] ^ w2[21] ^ w2[15] ^ w2[13]), 1);
    w2[30] = rotl((w2[27] ^ w2[22] ^ w2[16] ^ w2[14]), 1);
    w2[31] = rotl((w2[28] ^ w2[23] ^ w2[17] ^ w2[15]), 1);
    w2[32] = rotl((w2[29] ^ w2[24] ^ w2[18] ^ w2[16]), 1);
    w2[33] = rotl((w2[30] ^ w2[25] ^ w2[19] ^ w2[17]), 1);
    w2[34] = rotl((w2[31] ^ w2[26] ^ w2[20] ^ w2[18]), 1);
    w2[35] = rotl((w2[32] ^ w2[27] ^ w2[21] ^ w2[19]), 1);
    w2[36] = rotl((w2[33] ^ w2[28] ^ w2[22] ^ w2[20]), 1);
    w2[37] = rotl((w2[34] ^ w2[29] ^ w2[23] ^ w2[21]), 1);
    w2[38] = rotl((w2[35] ^ w2[30] ^ w2[24] ^ w2[22]), 1);
    w2[39] = rotl((w2[36] ^ w2[31] ^ w2[25] ^ w2[23]), 1);
    w2[40] = rotl((w2[37] ^ w2[32] ^ w2[26] ^ w2[24]), 1);
    w2[41] = rotl((w2[38] ^ w2[33] ^ w2[27] ^ w2[25]), 1);
    w2[42] = rotl((w2[39] ^ w2[34] ^ w2[28] ^ w2[26]), 1);
    w2[43] = rotl((w2[40] ^ w2[35] ^ w2[29] ^ w2[27]), 1);
    w2[44] = rotl((w2[41] ^ w2[36] ^ w2[30] ^ w2[28]), 1);
    w2[45] = rotl((w2[42] ^ w2[37] ^ w2[31] ^ w2[29]), 1);
    w2[46] = rotl((w2[43] ^ w2[38] ^ w2[32] ^ w2[30]), 1);
    w2[47] = rotl((w2[44] ^ w2[39] ^ w2[33] ^ w2[31]), 1);
    w2[48] = rotl((w2[45] ^ w2[40] ^ w2[34] ^ w2[32]), 1);
    w2[49] = rotl((w2[46] ^ w2[41] ^ w2[35] ^ w2[33]), 1);
    w2[50] = rotl((w2[47] ^ w2[42] ^ w2[36] ^ w2[34]), 1);
    w2[51] = rotl((w2[48] ^ w2[43] ^ w2[37] ^ w2[35]), 1);
    w2[52] = rotl((w2[49] ^ w2[44] ^ w2[38] ^ w2[36]), 1);
    w2[53] = rotl((w2[50] ^ w2[45] ^ w2[39] ^ w2[37]), 1);
    w2[54] = rotl((w2[51] ^ w2[46] ^ w2[40] ^ w2[38]), 1);
    w2[55] = rotl((w2[52] ^ w2[47] ^ w2[41] ^ w2[39]), 1);
    w2[56] = rotl((w2[53] ^ w2[48] ^ w2[42] ^ w2[40]), 1);
    w2[57] = rotl((w2[54] ^ w2[49] ^ w2[43] ^ w2[41]), 1);
    w2[58] = rotl((w2[55] ^ w2[50] ^ w2[44] ^ w2[42]), 1);
    w2[59] = rotl((w2[56] ^ w2[51] ^ w2[45] ^ w2[43]), 1);
    w2[60] = rotl((w2[57] ^ w2[52] ^ w2[46] ^ w2[44]), 1);
    w2[61] = rotl((w2[58] ^ w2[53] ^ w2[47] ^ w2[45]), 1);
    w2[62] = rotl((w2[59] ^ w2[54] ^ w2[48] ^ w2[46]), 1);
    w2[63] = rotl((w2[60] ^ w2[55] ^ w2[49] ^ w2[47]), 1);
    w2[64] = rotl((w2[61] ^ w2[56] ^ w2[50] ^ w2[48]), 1);
    w2[65] = rotl((w2[62] ^ w2[57] ^ w2[51] ^ w2[49]), 1);
    w2[66] = rotl((w2[63] ^ w2[58] ^ w2[52] ^ w2[50]), 1);
    w2[67] = rotl((w2[64] ^ w2[59] ^ w2[53] ^ w2[51]), 1);
    w2[68] = rotl((w2[65] ^ w2[60] ^ w2[54] ^ w2[52]), 1);
    w2[69] = rotl((w2[66] ^ w2[61] ^ w2[55] ^ w2[53]), 1);
    w2[70] = rotl((w2[67] ^ w2[62] ^ w2[56] ^ w2[54]), 1);
    w2[71] = rotl((w2[68] ^ w2[63] ^ w2[57] ^ w2[55]), 1);
    w2[72] = rotl((w2[69] ^ w2[64] ^ w2[58] ^ w2[56]), 1);
    w2[73] = rotl((w2[70] ^ w2[65] ^ w2[59] ^ w2[57]), 1);
    w2[74] = rotl((w2[71] ^ w2[66] ^ w2[60] ^ w2[58]), 1);
    w2[75] = rotl((w2[72] ^ w2[67] ^ w2[61] ^ w2[59]), 1);
    w2[76] = rotl((w2[73] ^ w2[68] ^ w2[62] ^ w2[60]), 1);
    w2[77] = rotl((w2[74] ^ w2[69] ^ w2[63] ^ w2[61]), 1);
    w2[78] = rotl((w2[75] ^ w2[70] ^ w2[64] ^ w2[62]), 1);
    w2[79] = rotl((w2[76] ^ w2[71] ^ w2[65] ^ w2[63]), 1);

    // Extend the 16 32-bit words into 80 32-bit words w3
    w3[16] = rotl((w3[13] ^ w3[8] ^ w3[2] ^ w3[0]), 1);
    w3[17] = rotl((w3[14] ^ w3[9] ^ w3[3] ^ w3[1]), 1);
    w3[18] = rotl((w3[15] ^ w3[10] ^ w3[4] ^ w3[2]), 1);
    w3[19] = rotl((w3[16] ^ w3[11] ^ w3[5] ^ w3[3]), 1);
    w3[20] = rotl((w3[17] ^ w3[12] ^ w3[6] ^ w3[4]), 1);
    w3[21] = rotl((w3[18] ^ w3[13] ^ w3[7] ^ w3[5]), 1);
    w3[22] = rotl((w3[19] ^ w3[14] ^ w3[8] ^ w3[6]), 1);
    w3[23] = rotl((w3[20] ^ w3[15] ^ w3[9] ^ w3[7]), 1);
    w3[24] = rotl((w3[21] ^ w3[16] ^ w3[10] ^ w3[8]), 1);
    w3[25] = rotl((w3[22] ^ w3[17] ^ w3[11] ^ w3[9]), 1);
    w3[26] = rotl((w3[23] ^ w3[18] ^ w3[12] ^ w3[10]), 1);
    w3[27] = rotl((w3[24] ^ w3[19] ^ w3[13] ^ w3[11]), 1);
    w3[28] = rotl((w3[25] ^ w3[20] ^ w3[14] ^ w3[12]), 1);
    w3[29] = rotl((w3[26] ^ w3[21] ^ w3[15] ^ w3[13]), 1);
    w3[30] = rotl((w3[27] ^ w3[22] ^ w3[16] ^ w3[14]), 1);
    w3[31] = rotl((w3[28] ^ w3[23] ^ w3[17] ^ w3[15]), 1);
    w3[32] = rotl((w3[29] ^ w3[24] ^ w3[18] ^ w3[16]), 1);
    w3[33] = rotl((w3[30] ^ w3[25] ^ w3[19] ^ w3[17]), 1);
    w3[34] = rotl((w3[31] ^ w3[26] ^ w3[20] ^ w3[18]), 1);
    w3[35] = rotl((w3[32] ^ w3[27] ^ w3[21] ^ w3[19]), 1);
    w3[36] = rotl((w3[33] ^ w3[28] ^ w3[22] ^ w3[20]), 1);
    w3[37] = rotl((w3[34] ^ w3[29] ^ w3[23] ^ w3[21]), 1);
    w3[38] = rotl((w3[35] ^ w3[30] ^ w3[24] ^ w3[22]), 1);
    w3[39] = rotl((w3[36] ^ w3[31] ^ w3[25] ^ w3[23]), 1);
    w3[40] = rotl((w3[37] ^ w3[32] ^ w3[26] ^ w3[24]), 1);
    w3[41] = rotl((w3[38] ^ w3[33] ^ w3[27] ^ w3[25]), 1);
    w3[42] = rotl((w3[39] ^ w3[34] ^ w3[28] ^ w3[26]), 1);
    w3[43] = rotl((w3[40] ^ w3[35] ^ w3[29] ^ w3[27]), 1);
    w3[44] = rotl((w3[41] ^ w3[36] ^ w3[30] ^ w3[28]), 1);
    w3[45] = rotl((w3[42] ^ w3[37] ^ w3[31] ^ w3[29]), 1);
    w3[46] = rotl((w3[43] ^ w3[38] ^ w3[32] ^ w3[30]), 1);
    w3[47] = rotl((w3[44] ^ w3[39] ^ w3[33] ^ w3[31]), 1);
    w3[48] = rotl((w3[45] ^ w3[40] ^ w3[34] ^ w3[32]), 1);
    w3[49] = rotl((w3[46] ^ w3[41] ^ w3[35] ^ w3[33]), 1);
    w3[50] = rotl((w3[47] ^ w3[42] ^ w3[36] ^ w3[34]), 1);
    w3[51] = rotl((w3[48] ^ w3[43] ^ w3[37] ^ w3[35]), 1);
    w3[52] = rotl((w3[49] ^ w3[44] ^ w3[38] ^ w3[36]), 1);
    w3[53] = rotl((w3[50] ^ w3[45] ^ w3[39] ^ w3[37]), 1);
    w3[54] = rotl((w3[51] ^ w3[46] ^ w3[40] ^ w3[38]), 1);
    w3[55] = rotl((w3[52] ^ w3[47] ^ w3[41] ^ w3[39]), 1);
    w3[56] = rotl((w3[53] ^ w3[48] ^ w3[42] ^ w3[40]), 1);
    w3[57] = rotl((w3[54] ^ w3[49] ^ w3[43] ^ w3[41]), 1);
    w3[58] = rotl((w3[55] ^ w3[50] ^ w3[44] ^ w3[42]), 1);
    w3[59] = rotl((w3[56] ^ w3[51] ^ w3[45] ^ w3[43]), 1);
    w3[60] = rotl((w3[57] ^ w3[52] ^ w3[46] ^ w3[44]), 1);
    w3[61] = rotl((w3[58] ^ w3[53] ^ w3[47] ^ w3[45]), 1);
    w3[62] = rotl((w3[59] ^ w3[54] ^ w3[48] ^ w3[46]), 1);
    w3[63] = rotl((w3[60] ^ w3[55] ^ w3[49] ^ w3[47]), 1);
    w3[64] = rotl((w3[61] ^ w3[56] ^ w3[50] ^ w3[48]), 1);
    w3[65] = rotl((w3[62] ^ w3[57] ^ w3[51] ^ w3[49]), 1);
    w3[66] = rotl((w3[63] ^ w3[58] ^ w3[52] ^ w3[50]), 1);
    w3[67] = rotl((w3[64] ^ w3[59] ^ w3[53] ^ w3[51]), 1);
    w3[68] = rotl((w3[65] ^ w3[60] ^ w3[54] ^ w3[52]), 1);
    w3[69] = rotl((w3[66] ^ w3[61] ^ w3[55] ^ w3[53]), 1);
    w3[70] = rotl((w3[67] ^ w3[62] ^ w3[56] ^ w3[54]), 1);
    w3[71] = rotl((w3[68] ^ w3[63] ^ w3[57] ^ w3[55]), 1);
    w3[72] = rotl((w3[69] ^ w3[64] ^ w3[58] ^ w3[56]), 1);
    w3[73] = rotl((w3[70] ^ w3[65] ^ w3[59] ^ w3[57]), 1);
    w3[74] = rotl((w3[71] ^ w3[66] ^ w3[60] ^ w3[58]), 1);
    w3[75] = rotl((w3[72] ^ w3[67] ^ w3[61] ^ w3[59]), 1);
    w3[76] = rotl((w3[73] ^ w3[68] ^ w3[62] ^ w3[60]), 1);
    w3[77] = rotl((w3[74] ^ w3[69] ^ w3[63] ^ w3[61]), 1);
    w3[78] = rotl((w3[75] ^ w3[70] ^ w3[64] ^ w3[62]), 1);
    w3[79] = rotl((w3[76] ^ w3[71] ^ w3[65] ^ w3[63]), 1);

    // Extend the 16 32-bit words into 80 32-bit words w4
    w4[16] = rotl((w4[13] ^ w4[8] ^ w4[2] ^ w4[0]), 1);
    w4[17] = rotl((w4[14] ^ w4[9] ^ w4[3] ^ w4[1]), 1);
    w4[18] = rotl((w4[15] ^ w4[10] ^ w4[4] ^ w4[2]), 1);
    w4[19] = rotl((w4[16] ^ w4[11] ^ w4[5] ^ w4[3]), 1);
    w4[20] = rotl((w4[17] ^ w4[12] ^ w4[6] ^ w4[4]), 1);
    w4[21] = rotl((w4[18] ^ w4[13] ^ w4[7] ^ w4[5]), 1);
    w4[22] = rotl((w4[19] ^ w4[14] ^ w4[8] ^ w4[6]), 1);
    w4[23] = rotl((w4[20] ^ w4[15] ^ w4[9] ^ w4[7]), 1);
    w4[24] = rotl((w4[21] ^ w4[16] ^ w4[10] ^ w4[8]), 1);
    w4[25] = rotl((w4[22] ^ w4[17] ^ w4[11] ^ w4[9]), 1);
    w4[26] = rotl((w4[23] ^ w4[18] ^ w4[12] ^ w4[10]), 1);
    w4[27] = rotl((w4[24] ^ w4[19] ^ w4[13] ^ w4[11]), 1);
    w4[28] = rotl((w4[25] ^ w4[20] ^ w4[14] ^ w4[12]), 1);
    w4[29] = rotl((w4[26] ^ w4[21] ^ w4[15] ^ w4[13]), 1);
    w4[30] = rotl((w4[27] ^ w4[22] ^ w4[16] ^ w4[14]), 1);
    w4[31] = rotl((w4[28] ^ w4[23] ^ w4[17] ^ w4[15]), 1);
    w4[32] = rotl((w4[29] ^ w4[24] ^ w4[18] ^ w4[16]), 1);
    w4[33] = rotl((w4[30] ^ w4[25] ^ w4[19] ^ w4[17]), 1);
    w4[34] = rotl((w4[31] ^ w4[26] ^ w4[20] ^ w4[18]), 1);
    w4[35] = rotl((w4[32] ^ w4[27] ^ w4[21] ^ w4[19]), 1);
    w4[36] = rotl((w4[33] ^ w4[28] ^ w4[22] ^ w4[20]), 1);
    w4[37] = rotl((w4[34] ^ w4[29] ^ w4[23] ^ w4[21]), 1);
    w4[38] = rotl((w4[35] ^ w4[30] ^ w4[24] ^ w4[22]), 1);
    w4[39] = rotl((w4[36] ^ w4[31] ^ w4[25] ^ w4[23]), 1);
    w4[40] = rotl((w4[37] ^ w4[32] ^ w4[26] ^ w4[24]), 1);
    w4[41] = rotl((w4[38] ^ w4[33] ^ w4[27] ^ w4[25]), 1);
    w4[42] = rotl((w4[39] ^ w4[34] ^ w4[28] ^ w4[26]), 1);
    w4[43] = rotl((w4[40] ^ w4[35] ^ w4[29] ^ w4[27]), 1);
    w4[44] = rotl((w4[41] ^ w4[36] ^ w4[30] ^ w4[28]), 1);
    w4[45] = rotl((w4[42] ^ w4[37] ^ w4[31] ^ w4[29]), 1);
    w4[46] = rotl((w4[43] ^ w4[38] ^ w4[32] ^ w4[30]), 1);
    w4[47] = rotl((w4[44] ^ w4[39] ^ w4[33] ^ w4[31]), 1);
    w4[48] = rotl((w4[45] ^ w4[40] ^ w4[34] ^ w4[32]), 1);
    w4[49] = rotl((w4[46] ^ w4[41] ^ w4[35] ^ w4[33]), 1);
    w4[50] = rotl((w4[47] ^ w4[42] ^ w4[36] ^ w4[34]), 1);
    w4[51] = rotl((w4[48] ^ w4[43] ^ w4[37] ^ w4[35]), 1);
    w4[52] = rotl((w4[49] ^ w4[44] ^ w4[38] ^ w4[36]), 1);
    w4[53] = rotl((w4[50] ^ w4[45] ^ w4[39] ^ w4[37]), 1);
    w4[54] = rotl((w4[51] ^ w4[46] ^ w4[40] ^ w4[38]), 1);
    w4[55] = rotl((w4[52] ^ w4[47] ^ w4[41] ^ w4[39]), 1);
    w4[56] = rotl((w4[53] ^ w4[48] ^ w4[42] ^ w4[40]), 1);
    w4[57] = rotl((w4[54] ^ w4[49] ^ w4[43] ^ w4[41]), 1);
    w4[58] = rotl((w4[55] ^ w4[50] ^ w4[44] ^ w4[42]), 1);
    w4[59] = rotl((w4[56] ^ w4[51] ^ w4[45] ^ w4[43]), 1);
    w4[60] = rotl((w4[57] ^ w4[52] ^ w4[46] ^ w4[44]), 1);
    w4[61] = rotl((w4[58] ^ w4[53] ^ w4[47] ^ w4[45]), 1);
    w4[62] = rotl((w4[59] ^ w4[54] ^ w4[48] ^ w4[46]), 1);
    w4[63] = rotl((w4[60] ^ w4[55] ^ w4[49] ^ w4[47]), 1);
    w4[64] = rotl((w4[61] ^ w4[56] ^ w4[50] ^ w4[48]), 1);
    w4[65] = rotl((w4[62] ^ w4[57] ^ w4[51] ^ w4[49]), 1);
    w4[66] = rotl((w4[63] ^ w4[58] ^ w4[52] ^ w4[50]), 1);
    w4[67] = rotl((w4[64] ^ w4[59] ^ w4[53] ^ w4[51]), 1);
    w4[68] = rotl((w4[65] ^ w4[60] ^ w4[54] ^ w4[52]), 1);
    w4[69] = rotl((w4[66] ^ w4[61] ^ w4[55] ^ w4[53]), 1);
    w4[70] = rotl((w4[67] ^ w4[62] ^ w4[56] ^ w4[54]), 1);
    w4[71] = rotl((w4[68] ^ w4[63] ^ w4[57] ^ w4[55]), 1);
    w4[72] = rotl((w4[69] ^ w4[64] ^ w4[58] ^ w4[56]), 1);
    w4[73] = rotl((w4[70] ^ w4[65] ^ w4[59] ^ w4[57]), 1);
    w4[74] = rotl((w4[71] ^ w4[66] ^ w4[60] ^ w4[58]), 1);
    w4[75] = rotl((w4[72] ^ w4[67] ^ w4[61] ^ w4[59]), 1);
    w4[76] = rotl((w4[73] ^ w4[68] ^ w4[62] ^ w4[60]), 1);
    w4[77] = rotl((w4[74] ^ w4[69] ^ w4[63] ^ w4[61]), 1);
    w4[78] = rotl((w4[75] ^ w4[70] ^ w4[64] ^ w4[62]), 1);
    w4[79] = rotl((w4[76] ^ w4[71] ^ w4[65] ^ w4[63]), 1);

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

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[2], w2[2], w3[2], w4[2]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[3], w2[3], w3[3], w4[3]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[4], w2[4], w3[4], w4[4]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[5], w2[5], w3[5], w4[5]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[6], w2[6], w3[6], w4[6]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[7], w2[7], w3[7], w4[7]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[8], w2[8], w3[8], w4[8]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[9], w2[9], w3[9], w4[9]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[10], w2[10], w3[10], w4[10]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[11], w2[11], w3[11], w4[11]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[12], w2[12], w3[12], w4[12]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[13], w2[13], w3[13], w4[13]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[14], w2[14], w3[14], w4[14]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[15], w2[15], w3[15], w4[15]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[16], w2[16], w3[16], w4[16]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[17], w2[17], w3[17], w4[17]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[18], w2[18], w3[18], w4[18]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f1(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[19], w2[19], w3[19], w4[19]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    // -----------------------------------------

    k = 0x6ED9EBA1;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[20], w2[20], w3[20], w4[20]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[21], w2[21], w3[21], w4[21]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[22], w2[22], w3[22], w4[22]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[23], w2[23], w3[23], w4[23]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[24], w2[24], w3[24], w4[24]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[25], w2[25], w3[25], w4[25]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[26], w2[26], w3[26], w4[26]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[27], w2[27], w3[27], w4[27]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[28], w2[28], w3[28], w4[28]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[29], w2[29], w3[29], w4[29]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[30], w2[30], w3[30], w4[30]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[31], w2[31], w3[31], w4[31]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[32], w2[32], w3[32], w4[32]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[33], w2[33], w3[33], w4[33]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[34], w2[34], w3[34], w4[34]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[35], w2[35], w3[35], w4[35]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[36], w2[36], w3[36], w4[36]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[37], w2[37], w3[37], w4[37]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[38], w2[38], w3[38], w4[38]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f2(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[39], w2[39], w3[39], w4[39]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    // -----------------------

    k = 0x8F1BBCDC;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[40], w2[40], w3[40], w4[40]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[41], w2[41], w3[41], w4[41]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[42], w2[42], w3[42], w4[42]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[43], w2[43], w3[43], w4[43]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[44], w2[44], w3[44], w4[44]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[45], w2[45], w3[45], w4[45]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[46], w2[46], w3[46], w4[46]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[47], w2[47], w3[47], w4[47]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[48], w2[48], w3[48], w4[48]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[49], w2[49], w3[49], w4[49]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[50], w2[50], w3[50], w4[50]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[51], w2[51], w3[51], w4[51]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[52], w2[52], w3[52], w4[52]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[53], w2[53], w3[53], w4[53]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[54], w2[54], w3[54], w4[54]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[55], w2[55], w3[55], w4[55]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[56], w2[56], w3[56], w4[56]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[57], w2[57], w3[57], w4[57]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[58], w2[58], w3[58], w4[58]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f3(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[59], w2[59], w3[59], w4[59]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    // ------------------------------------

    k = 0xCA62C1D6;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[60], w2[60], w3[60], w4[60]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[61], w2[61], w3[61], w4[61]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[62], w2[62], w3[62], w4[62]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[63], w2[63], w3[63], w4[63]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[64], w2[64], w3[64], w4[64]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[65], w2[65], w3[65], w4[65]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[66], w2[66], w3[66], w4[66]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[67], w2[67], w3[67], w4[67]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[68], w2[68], w3[68], w4[68]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[69], w2[69], w3[69], w4[69]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[70], w2[70], w3[70], w4[70]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[71], w2[71], w3[71], w4[71]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[72], w2[72], w3[72], w4[72]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[73], w2[73], w3[73], w4[73]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[74], w2[74], w3[74], w4[74]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[75], w2[75], w3[75], w4[75]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[76], w2[76], w3[76], w4[76]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[77], w2[77], w3[77], w4[77]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[78], w2[78], w3[78], w4[78]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    vecF = f4(vecB,vecC,vecD);
    vecTemp = temp(vecA, vecE, vecF, k, w1[79], w2[79], w3[79], w4[79]);
    vecE = vecD;
    vecD = vecC;
    vecC = setC(vecB);
    vecB = vecA;
    vecA = vecTemp;

    // -----------------------------

    // Put the new values into the hash_buffer
    hash_buffer1[0] += ((uint32_t*)&vecA)[0];
    hash_buffer1[1] += ((uint32_t*)&vecB)[0];
    hash_buffer1[2] += ((uint32_t*)&vecC)[0];
    hash_buffer1[3] += ((uint32_t*)&vecD)[0];
    hash_buffer1[4] += ((uint32_t*)&vecE)[0];

    hash_buffer2[0] += ((uint32_t*)&vecA)[1];
    hash_buffer2[1] += ((uint32_t*)&vecB)[1];
    hash_buffer2[2] += ((uint32_t*)&vecC)[1];
    hash_buffer2[3] += ((uint32_t*)&vecD)[1];
    hash_buffer2[4] += ((uint32_t*)&vecE)[1];

    hash_buffer3[0] += ((uint32_t*)&vecA)[2];
    hash_buffer3[1] += ((uint32_t*)&vecB)[2];
    hash_buffer3[2] += ((uint32_t*)&vecC)[2];
    hash_buffer3[3] += ((uint32_t*)&vecD)[2];
    hash_buffer3[4] += ((uint32_t*)&vecE)[2];

    hash_buffer4[0] += ((uint32_t*)&vecA)[3];
    hash_buffer4[1] += ((uint32_t*)&vecB)[3];
    hash_buffer4[2] += ((uint32_t*)&vecC)[3];
    hash_buffer4[3] += ((uint32_t*)&vecD)[3];
    hash_buffer4[4] += ((uint32_t*)&vecE)[3];
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

bool SHAcompare(uint32_t hash_buffer[5], uint32_t input_hash[5])
{
    return !memcmp(hash_buffer, input_hash, 20);
}
