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
//	-  pthreads
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
#include <pthread.h>
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

#define rotl(value, shift) ((value << shift) | (value >> (32 - shift)))

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

#define N 52
#define string_size 10

//********************************************************************
//	Function Prototypes
//********************************************************************

void SHA1(char* message1, char* message2, char* message3, char* message4,
        uint32_t hash_buffer1[5], uint32_t hash_buffer2[5], uint32_t hash_buffer3[5], uint32_t hash_buffer4[5], uint32_t message_size, uint32_t thread_number);
void prepMessage(char* message, uint32_t chunks[][16], uint64_t message_size_bytes);
void shaIteration(uint32_t hash_buffer1[5], uint32_t hash_buffer2[5], uint32_t hash_buffer3[5], uint32_t hash_buffer4[5],
        uint32_t chunk1[16], uint32_t chunk2[16], uint32_t chunk3[16], uint32_t chunk4[16], uint32_t thread_number);
void printSHA(uint32_t hash_buffer[5]);
bool SHAcompare(uint32_t hash_buffer[5], uint32_t input_hash[5]);
bool SHAcompareVEC(__m128i vecInput1, __m128i vecResult1, uint32_t vecInput2, uint32_t vecResult2);

//********************************************************************
//	Function for Threads setup
//********************************************************************

typedef struct character_set_thread_data
{
    uint32_t thread_no;
    char starting_password[10];
    char ending_password[10];
    uint32_t starting_length;
    uint32_t compare_hash[5];
} thread_data;

void generateCharacterSet(void *ptr);

int8_t password_found = -1;

//********************************************************************
//	Main Function
//********************************************************************

int main(int argc, char** argv)
{
    // Input hash
    uint32_t input_hash[5];
    printf("argv[1] = %s\n", argv[1]);

    sscanf(argv[1], "%8x%8x%8x%8x%8x", &input_hash[0], &input_hash[1],
            &input_hash[2], &input_hash[3], &input_hash[4]);

    // Define the variables for timing
    struct timeval start, end;

    // Declare the threads
    pthread_t thread0, thread1;

    // Create the staring and ending strings to check for
    char starting_password1[] = { 'a' };
    char starting_password2[] = { 'a' , 'a', 'a', 'a', 'a', 'A'};

    char ending_password1[] = { 'Z' , 'Z', 'Z', 'Z', 'Z', 'z'};
    char ending_password2[] = { 'Z' , 'Z', 'Z', 'Z', 'Z', 'Z'};

    thread_data data0, data1;

    // number the threads
    data0.thread_no = 0;
    data1.thread_no = 1;

    // Copy over the starting password
    memcpy(data0.starting_password, starting_password1, sizeof(data0.starting_password));
    memcpy(data1.starting_password, starting_password2, sizeof(data1.starting_password));

    // Copy over the ending password
    memcpy(data0.ending_password, ending_password1, sizeof(data0.ending_password));
    memcpy(data1.ending_password, ending_password2, sizeof(data1.ending_password));

    // Give the correct lengths
    data0.starting_length = 1;
    data1.starting_length = 6;

    // Copy over the hash to compare
    memcpy(data0.compare_hash, input_hash, sizeof(data0.compare_hash));
    memcpy(data1.compare_hash, input_hash, sizeof(data1.compare_hash));
    
    // get the start time
    gettimeofday(&start, NULL);

    // Spawn the threads
    pthread_create(&thread0, NULL, (void*)&generateCharacterSet, (void*)&data0);
    pthread_create(&thread1, NULL, (void*)&generateCharacterSet, (void*)&data1);
    
    while(password_found < 0) 
    {
    }

    gettimeofday(&end, NULL);
    // Take the difference to get the total time taken
    printf("TIME: %ldus\n", ((end.tv_sec * 1000000 + end.tv_usec)
                - (start.tv_sec * 1000000 + start.tv_usec)));

    printf("password_found: %d\n", password_found);

    pthread_join(thread0, NULL);
    pthread_join(thread1, NULL);

    /*switch(password_found)
    {
        case 0:
            printf("Canceling threads: 1\n");
            pthread_join(thread0, NULL);
            pthread_kill(thread1, 1);
            break;
        case 1:
            printf("Canceling threads: 0\n");
            pthread_join(thread1, NULL);
            pthread_kill(thread0, 1);
            break;
    }*/


    // Initialize hash_buffer
    //End program
    return 0;
}

//********************************************************************
//	Function Definitions
//********************************************************************

void generateCharacterSet(void *ptr)
{
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    // declare a thread_data pointer
    // to hold all the input data
    thread_data *data;

    // set the data equal to the input
    data = (thread_data*)ptr;

    uint32_t thread_number = data->thread_no;

    // declare the compare_hash array
    uint32_t compare_hash[5];

    // declare the starting and ending password for
    // this function
    char starting_password[10];
    char ending_password[10];

    // declare the starting length
    uint32_t starting_length = data->starting_length;

    // Copy over the character set and the hash to compare against
    memcpy(starting_password, data->starting_password, sizeof(starting_password));
    memcpy(ending_password, data->ending_password, sizeof(ending_password));
    memcpy(compare_hash, data->compare_hash, sizeof(compare_hash));

    // Start generating passwords up to length 10 for the character_set given

    // Declare the hash_buffers for SHA1
    uint32_t hash_buffer1[5];
    uint32_t hash_buffer2[5];
    uint32_t hash_buffer3[5];
    uint32_t hash_buffer4[5];

    char password1[10];
    char password2[10];
    char password3[10];
    char password4[10];

    // Copy over the starting passworrd to the password string
    memcpy(password1, starting_password, sizeof(password1));
    memcpy(password2, starting_password, sizeof(password2));
    memcpy(password3, starting_password, sizeof(password3));
    memcpy(password4, starting_password, sizeof(password4));

    uint32_t i,j,k,l,m,n,o,p,q,r,s,index1,index2;

    uint32_t j0,k0,l0,m0,n0,o0,q0,p0,r0,s0;

    // Figure out the starting position for all the loops
    for(index1 = 0; index1 < starting_length; ++index1)
    {
        for(index2 = 0; index2 < N; ++index2)
        {
           if(character_set[index2] == starting_password[index1])
           {
               if(starting_length - 1 - index1 == 0)
               {
                    j0 = index2;
                    //printf("j0: %d\n", j0);
               }
               else if(starting_length - 1 - index1 == 1)
               {
                    k0 = index2;
                    //printf("k0: %d\n", k0);
               }
               else if(starting_length - 1 - index1 == 2)
               {
                    l0 = index2;
                    //printf("l0: %d\n", l0);
               }
               else if(starting_length - 1 - index1 == 3)
               {
                    m0 = index2;
                    //printf("m0: %d\n", m0);
               }
               else if(starting_length - 1 - index1 == 4)
               {
                    n0 = index2;
                    //printf("n0: %d\n", n0);
               }
               else if(starting_length - 1 - index1 == 5)
               {
                    o0 = index2;
                    //printf("o0: %d\n", o0);
               }
               else if(starting_length - 1 - index1 == 6)
               {
                    p0 = index2;
                    //printf("p0: %d\n", p0);
               }
               else if(starting_length - 1 - index1 == 7)
               {
                    q0 = index2;
                    //printf("q0: %d\n", q0);
               }
               else if(starting_length - 1 - index1 == 8)
               {
                    r0 = index2;
                    //printf("r0: %d\n", r0);
               }
               else if(starting_length - 1 - index1 == 9)
               {
                    s0 = index2;
                    //printf("s0: %d\n", s0);
               }
           }
        }
    }

    for(i = starting_length - 1; i < string_size; ++i)
    {
        for(j = j0; (j < N); j++)
        {
            // If this is the first time here,
            if(i == 0)
            {
                password1[0] = character_set[j++];
                password2[0] = character_set[j++];
                password3[0] = character_set[j++];
                password4[0] = character_set[j];
                SHA1(password1, password2, password3, password4,
                        hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 1, thread_number);

                if(SHAcompare(hash_buffer1, compare_hash))
                {
                    printf("Found match!\nPassword %s\nThread: %d\n", password1, thread_number);
                    printSHA(hash_buffer1);
                    password_found = thread_number;
                    pthread_exit(0);
                }
                else if(SHAcompare(hash_buffer2, compare_hash))
                {
                    printf("Found match!\nPassword %s\nThread: %d\n", password2, thread_number);
                    printSHA(hash_buffer2);
                    password_found = thread_number;
                    pthread_exit(0);
                }
                else if(SHAcompare(hash_buffer3, compare_hash))
                {
                    printf("Found match!\nPassword %s\nThread: %d\n", password3, thread_number);
                    printSHA(hash_buffer3);
                    password_found = thread_number;
                    pthread_exit(0);
                }
                else if(SHAcompare(hash_buffer4, compare_hash))
                {
                    printf("Found match!\nPassword %s\nThread: %d\n", password4, thread_number);
                    printSHA(hash_buffer4);
                    password_found = thread_number;
                    pthread_exit(0);
                }
            }
            else
            {
                password1[i] = character_set[j];
                password2[i] = character_set[j];
                password3[i] = character_set[j];
                password4[i] = character_set[j];
            }
            if(password_found >= 0)
            {
                pthread_exit(0);
            }
            for(k = k0; (k < N) && (i >= 1); k++)
            {
                if(i == 1)
                {
                    password1[0] = character_set[k++];
                    password2[0] = character_set[k++];
                    password3[0] = character_set[k++];
                    password4[0] = character_set[k];
                    SHA1(password1, password2, password3, password4,
                            hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 2, thread_number);
                    if(SHAcompare(hash_buffer1, compare_hash))
                    {
                        printf("Found match!\nPassword %s\nThread: %d\n", password1, thread_number);
                        printSHA(hash_buffer1);
                        password_found = thread_number;
                        pthread_exit(0);
                    }
                    else if(SHAcompare(hash_buffer2, compare_hash))
                    {
                        printf("Found match!\nPassword %s\nThread: %d\n", password2, thread_number);
                        printSHA(hash_buffer2);
                        password_found = thread_number;
                        pthread_exit(0);
                    }
                    else if(SHAcompare(hash_buffer3, compare_hash))
                    {
                        printf("Found match!\nPassword %s\nThread: %d\n", password3, thread_number);
                        printSHA(hash_buffer3);
                        password_found = thread_number;
                        pthread_exit(0);
                    }
                    else if(SHAcompare(hash_buffer4, compare_hash))
                    {
                        printf("Found match!\nPassword %s\nThread: %d\n", password4, thread_number);
                        printSHA(hash_buffer4);
                        password_found = thread_number;
                        pthread_exit(0);
                    }
                }
                else
                {
                    password1[i - 1] = character_set[k];
                    password2[i - 1] = character_set[k];
                    password3[i - 1] = character_set[k];
                    password4[i - 1] = character_set[k];
                }
                if(password_found >= 0)
                {
                    pthread_exit(0);
                }

                for(l = l0; (l < N) && (i >= 2); l++)
                {
                    if(i == 2)
                    {
                        password1[0] = character_set[l++];
                        password2[0] = character_set[l++];
                        password3[0] = character_set[l++];
                        password4[0] = character_set[l];
                        SHA1(password1, password2, password3, password4,
                                hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 3, thread_number);
                        if(SHAcompare(hash_buffer1, compare_hash))
                        {
                            printf("Found match!\nPassword %s\nThread: %d\n", password1, thread_number);
                            printSHA(hash_buffer1);
                            password_found = thread_number;
                            pthread_exit(0);
                        }
                        else if(SHAcompare(hash_buffer2, compare_hash))
                        {
                            printf("Found match!\nPassword %s\nThread: %d\n", password2, thread_number);
                            printSHA(hash_buffer2);
                            password_found = thread_number;
                            pthread_exit(0);
                        }
                        else if(SHAcompare(hash_buffer3, compare_hash))
                        {
                            printf("Found match!\nPassword %s\nThread: %d\n", password3, thread_number);
                            printSHA(hash_buffer3);
                            password_found = thread_number;
                            pthread_exit(0);
                        }
                        else if(SHAcompare(hash_buffer4, compare_hash))
                        {
                            printf("Found match!\nPassword %s\nThread: %d\n", password4, thread_number);
                            printSHA(hash_buffer4);
                            password_found = thread_number;
                            pthread_exit(0);
                        }
                    }
                    else
                    {
                        password1[i - 2] = character_set[l];
                        password2[i - 2] = character_set[l];
                        password3[i - 2] = character_set[l];
                        password4[i - 2] = character_set[l];
                    }
                    if(password_found >= 0)
                    {
                        pthread_exit(0);
                    }
                    for(m = m0; (m < N) && (i >= 3); m++)
                    {
                        if(i == 3)
                        {
                            password1[0] = character_set[m++];
                            password2[0] = character_set[m++];
                            password3[0] = character_set[m++];
                            password4[0] = character_set[m];
                            SHA1(password1, password2, password3, password4,
                                    hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 4, thread_number);
                            if(SHAcompare(hash_buffer1, compare_hash))
                            {
                                printf("Found match!\nPassword %s\nThread: %d\n", password1, thread_number);
                                printSHA(hash_buffer1);
                                password_found = thread_number;
                                pthread_exit(0);
                            }
                            else if(SHAcompare(hash_buffer2, compare_hash))
                            {
                                printf("Found match!\nPassword %s\nThread: %d\n", password2, thread_number);
                                printSHA(hash_buffer2);
                                password_found = thread_number;
                                pthread_exit(0);
                            }
                            else if(SHAcompare(hash_buffer3, compare_hash))
                            {
                                printf("Found match!\nPassword %s\nThread: %d\n", password3, thread_number);
                                printSHA(hash_buffer3);
                                password_found = thread_number;
                                pthread_exit(0);
                            }
                            else if(SHAcompare(hash_buffer4, compare_hash))
                            {
                                printf("Found match!\nPassword %s\nThread: %d\n", password4, thread_number);
                                printSHA(hash_buffer4);
                                password_found = thread_number;
                                pthread_exit(0);
                            }
                        }
                        else
                        {
                            password1[i - 3] = character_set[m];
                            password2[i - 3] = character_set[m];
                            password3[i - 3] = character_set[m];
                            password4[i - 3] = character_set[m];
                        }
                        if(password_found >= 0)
                        {
                            pthread_exit(0);
                        }
                        for(n = n0; (n < N) && (i >= 4); n++)
                        {
                            if(i == 4)
                            {
                                password1[0] = character_set[n++];
                                password2[0] = character_set[n++];
                                password3[0] = character_set[n++];
                                password4[0] = character_set[n];
                                SHA1(password1, password2, password3, password4,
                                        hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 5, thread_number);
                                if(SHAcompare(hash_buffer1, compare_hash))
                                {
                                    printf("Found match!\nPassword %s\nThread: %d\n", password1, thread_number);
                                    printSHA(hash_buffer1);
                                    password_found = thread_number;
                                    pthread_exit(0);
                                }
                                else if(SHAcompare(hash_buffer2, compare_hash))
                                {
                                    printf("Found match!\nPassword %s\nThread: %d\n", password2, thread_number);
                                    printSHA(hash_buffer2);
                                    password_found = thread_number;
                                    pthread_exit(0);
                                }
                                else if(SHAcompare(hash_buffer3, compare_hash))
                                {
                                    printf("Found match!\nPassword %s\nThread: %d\n", password3, thread_number);
                                    printSHA(hash_buffer3);
                                    password_found = thread_number;
                                    pthread_exit(0);
                                }
                                else if(SHAcompare(hash_buffer4, compare_hash))
                                {
                                    printf("Found match!\nPassword %s\nThread: %d\n", password4, thread_number);
                                    printSHA(hash_buffer4);
                                    password_found = thread_number;
                                    pthread_exit(0);
                                }
                            }
                            else
                            {
                                password1[i - 4] = character_set[n];
                                password2[i - 4] = character_set[n];
                                password3[i - 4] = character_set[n];
                                password4[i - 4] = character_set[n];
                            }
                            if(password_found >= 0)
                            {
                                pthread_exit(0);
                            }
                            for(o = o0; (o < N) && (i >= 5); o++)
                            {
                                if(i == 5)
                                {
                                    password1[0] = character_set[o++];
                                    password2[0] = character_set[o++];
                                    password3[0] = character_set[o++];
                                    password4[0] = character_set[o];
                                    SHA1(password1, password2, password3, password4,
                                            hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 6, thread_number);
                                    if(SHAcompare(hash_buffer1, compare_hash))
                                    {
                                        printf("Found match!\nPassword %s\nThread: %d\n", password1, thread_number);
                                        printSHA(hash_buffer1);
                                        password_found = thread_number;
                                        pthread_exit(0);
                                    }
                                    else if(SHAcompare(hash_buffer2, compare_hash))
                                    {
                                        printf("Found match!\nPassword %s\nThread: %d\n", password2, thread_number);
                                        printSHA(hash_buffer2);
                                        password_found = thread_number;
                                        pthread_exit(0);
                                    }
                                    else if(SHAcompare(hash_buffer3, compare_hash))
                                    {
                                        printf("Found match!\nPassword %s\nThread: %d\n", password3, thread_number);
                                        printSHA(hash_buffer3);
                                        password_found = thread_number;
                                        pthread_exit(0);
                                    }
                                    else if(SHAcompare(hash_buffer4, compare_hash))
                                    {
                                        printf("Found match!\nPassword %s\nThread: %d\n", password4, thread_number);
                                        printSHA(hash_buffer4);
                                        password_found = thread_number;
                                        pthread_exit(0);
                                    }
                                }
                                else
                                {
                                    password1[i - 5] = character_set[o];
                                    password2[i - 5] = character_set[o];
                                    password3[i - 5] = character_set[o];
                                    password4[i - 5] = character_set[o];
                                }
                                if(password_found >= 0)
                                {
                                    pthread_exit(0);
                                }
                                for(p = p0; (p < N) && (i >= 6); p++)
                                {
                                    if(i == 6)
                                    {
                                        password1[0] = character_set[p++];
                                        password2[0] = character_set[p++];
                                        password3[0] = character_set[p++];
                                        password4[0] = character_set[p];
                                        SHA1(password1, password2, password3, password4,
                                                hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 7, thread_number);
                                        if(SHAcompare(hash_buffer1, compare_hash))
                                        {
                                            printf("Found match!\nPassword %s\nThread: %d\n", password1, thread_number);
                                            printSHA(hash_buffer1);
                                            password_found = thread_number;
                                            pthread_exit(0);
                                        }
                                        else if(SHAcompare(hash_buffer2, compare_hash))
                                        {
                                            printf("Found match!\nPassword %s\nThread: %d\n", password2, thread_number);
                                            printSHA(hash_buffer2);
                                            password_found = thread_number;
                                            pthread_exit(0);
                                        }
                                        else if(SHAcompare(hash_buffer3, compare_hash))
                                        {
                                            printf("Found match!\nPassword %s\nThread: %d\n", password3, thread_number);
                                            printSHA(hash_buffer3);
                                            password_found = thread_number;
                                            pthread_exit(0);
                                        }
                                        else if(SHAcompare(hash_buffer4, compare_hash))
                                        {
                                            printf("Found match!\nPassword %s\nThread: %d\n", password4, thread_number);
                                            printSHA(hash_buffer4);
                                            password_found = thread_number;
                                            pthread_exit(0);
                                        }
                                    }
                                    else
                                    {
                                        password1[i - 6] = character_set[p];
                                        password2[i - 6] = character_set[p];
                                        password3[i - 6] = character_set[p];
                                        password4[i - 6] = character_set[p];
                                    }
                                    if(!memcmp(password1, ending_password, sizeof(ending_password))
                                            || !memcmp(password2, ending_password, sizeof(ending_password))
                                            || !memcmp(password3, ending_password, sizeof(ending_password))
                                            || !memcmp(password4, ending_password, sizeof(ending_password)))
                                    {
                                        pthread_exit(0);
                                    }
                                    if(password_found >= 0)
                                    {
                                        pthread_exit(0);
                                    }
                                    for(q = q0; (q < N) && (i >= 7); q++)
                                    {
                                        if(i == 7)
                                        {
                                            password1[0] = character_set[q++];
                                            password2[0] = character_set[q++];
                                            password3[0] = character_set[q++];
                                            password4[0] = character_set[q];
                                            SHA1(password1, password2, password3, password4,
                                                    hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 8, thread_number);
                                            if(SHAcompare(hash_buffer1, compare_hash))
                                            {
                                                printf("Found match!\nPassword %s\nThread: %d\n", password1, thread_number);
                                                printSHA(hash_buffer1);
                                                password_found = thread_number;
                                                pthread_exit(0);
                                            }
                                            else if(SHAcompare(hash_buffer2, compare_hash))
                                            {
                                                printf("Found match!\nPassword %s\nThread: %d\n", password2, thread_number);
                                                printSHA(hash_buffer2);
                                                password_found = thread_number;
                                                pthread_exit(0);
                                            }
                                            else if(SHAcompare(hash_buffer3, compare_hash))
                                            {
                                                printf("Found match!\nPassword %s\nThread: %d\n", password3, thread_number);
                                                printSHA(hash_buffer3);
                                                password_found = thread_number;
                                                pthread_exit(0);
                                            }
                                            else if(SHAcompare(hash_buffer4, compare_hash))
                                            {
                                                printf("Found match!\nPassword %s\nThread: %d\n", password4, thread_number);
                                                printSHA(hash_buffer4);
                                                password_found = thread_number;
                                                pthread_exit(0);
                                            }
                                        }
                                        else
                                        {
                                            password1[i - 7] = character_set[q];
                                            password2[i - 7] = character_set[q];
                                            password3[i - 7] = character_set[q];
                                            password4[i - 7] = character_set[q];
                                        }
                                        for(r = r0; (r < N) && (i >= 8); r++)
                                        {
                                            if(i == 8)
                                            {
                                                password1[0] = character_set[r++];
                                                password2[0] = character_set[r++];
                                                password3[0] = character_set[r++];
                                                password4[0] = character_set[r];
                                                SHA1(password1, password2, password3, password4,
                                                        hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 9, thread_number);
                                                if(SHAcompare(hash_buffer1, compare_hash))
                                                {
                                                    printf("Found match!\nPassword %s\nThread: %d\n", password1, thread_number);
                                                    printSHA(hash_buffer1);
                                                    password_found = thread_number;
                                                    pthread_exit(0);
                                                }
                                                else if(SHAcompare(hash_buffer2, compare_hash))
                                                {
                                                    printf("Found match!\nPassword %s\nThread: %d\n", password2, thread_number);
                                                    printSHA(hash_buffer2);
                                                    password_found = thread_number;
                                                    pthread_exit(0);
                                                }
                                                else if(SHAcompare(hash_buffer3, compare_hash))
                                                {
                                                    printf("Found match!\nPassword %s\nThread: %d\n", password3, thread_number);
                                                    printSHA(hash_buffer3);
                                                    password_found = thread_number;
                                                    pthread_exit(0);
                                                }
                                                else if(SHAcompare(hash_buffer4, compare_hash))
                                                {
                                                    printf("Found match!\nPassword %s\nThread: %d\n", password4, thread_number);
                                                    printSHA(hash_buffer4);
                                                    password_found = thread_number;
                                                    pthread_exit(0);
                                                }
                                            }
                                            else
                                            {
                                                password1[i - 8] = character_set[r];
                                                password2[i - 8] = character_set[r];
                                                password3[i - 8] = character_set[r];
                                                password4[i - 8] = character_set[r];
                                            }
                                            for(s = s0; (s < N) && (i >= 9); s++)
                                            {
                                                if(i == 9)
                                                {
                                                    password1[0] = character_set[s++];
                                                    password2[0] = character_set[s++];
                                                    password3[0] = character_set[s++];
                                                    password4[0] = character_set[s];
                                                    SHA1(password1, password2, password3, password4,
                                                            hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, 10, thread_number);
                                                    if(SHAcompare(hash_buffer1, compare_hash))
                                                    {
                                                        printf("Found match!\nPassword %s\nThread: %d\n", password1, thread_number);
                                                        printSHA(hash_buffer1);
                                                        password_found = thread_number;
                                                        pthread_exit(0);
                                                    }
                                                    else if(SHAcompare(hash_buffer2, compare_hash))
                                                    {
                                                        printf("Found match!\nPassword %s\nThread: %d\n", password2, thread_number);
                                                        printSHA(hash_buffer2);
                                                        password_found = thread_number;
                                                        pthread_exit(0);
                                                    }
                                                    else if(SHAcompare(hash_buffer3, compare_hash))
                                                    {
                                                        printf("Found match!\nPassword %s\nThread: %d\n", password3, thread_number);
                                                        printSHA(hash_buffer3);
                                                        password_found = thread_number;
                                                        pthread_exit(0);
                                                    }
                                                    else if(SHAcompare(hash_buffer4, compare_hash))
                                                    {
                                                        printf("Found match!\nPassword %s\nThread: %d\n", password4, thread_number);
                                                        printSHA(hash_buffer4);
                                                        password_found = thread_number;
                                                        pthread_exit(0);
                                                    }
                                                }
                                                else
                                                {
                                                    password1[i - 9] = character_set[s];
                                                    password2[i - 9] = character_set[s];
                                                    password3[i - 9] = character_set[s];
                                                    password4[i - 9] = character_set[s];
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
    printf("Unable to find hash on thread %d: %x%x%x%x%x\n", thread_number, compare_hash[0], compare_hash[1], compare_hash[2], compare_hash[3], compare_hash[4]);


}

void SHA1(char* message1, char* message2, char* message3, char* message4, uint32_t hash_buffer1[5], uint32_t hash_buffer2[5], uint32_t hash_buffer3[5], uint32_t hash_buffer4[5], uint32_t message_size, uint32_t thread_number)
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
    shaIteration(hash_buffer1, hash_buffer2, hash_buffer3, hash_buffer4, chunks1[0], chunks2[0], chunks3[0], chunks4[0], thread_number);

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
        uint32_t chunk1[16], uint32_t chunk2[16], uint32_t chunk3[16], uint32_t chunk4[16], uint32_t thread_number)
{
    // Array to store the extended value
    static uint32_t w1_1[80];
    static uint32_t w2_1[80];
    static uint32_t w3_1[80];
    static uint32_t w4_1[80];

    static uint32_t w1_2[80];
    static uint32_t w2_2[80];
    static uint32_t w3_2[80];
    static uint32_t w4_2[80];

    //Preprocess extra 2048-bits
    static uint32_t PW[80];
    //static uint32_t PW[80];
    //static uint32_t PW[80];
    //static uint32_t PW[80];

    // Iterator variable
    uint16_t i;

    // Values for computation during the iteration
    uint32_t a, b, c, d, e, f, k, temp;
    //uint32_t k;

    if(thread_number == 0)
    {
        //Define w1[0], w2[0], w3[0], w4[0]
        w1_1[0] = chunk1[0];
        w2_1[0] = chunk2[0];
        w3_1[0] = chunk3[0];
        w4_1[0] = chunk4[0];

        uint32_t w1_0_1 = rotl(w1_1[0], 1);
        uint32_t w1_0_2 = rotl(w1_1[0], 2);
        uint32_t w1_0_3 = rotl(w1_1[0], 3);
        uint32_t w1_0_4 = rotl(w1_1[0], 4);
        uint32_t w1_0_5 = rotl(w1_1[0], 5);
        uint32_t w1_0_6 = rotl(w1_1[0], 6);
        uint32_t w1_0_7 = rotl(w1_1[0], 7);
        uint32_t w1_0_8 = rotl(w1_1[0], 8);
        uint32_t w1_0_9 = rotl(w1_1[0], 9);
        uint32_t w1_0_10 = rotl(w1_1[0], 10);
        uint32_t w1_0_11 = rotl(w1_1[0], 11);
        uint32_t w1_0_12 = rotl(w1_1[0], 12);
        uint32_t w1_0_13 = rotl(w1_1[0], 13);
        uint32_t w1_0_14 = rotl(w1_1[0], 14);
        uint32_t w1_0_15 = rotl(w1_1[0], 15);
        uint32_t w1_0_16 = rotl(w1_1[0], 16);
        uint32_t w1_0_17 = rotl(w1_1[0], 17);
        uint32_t w1_0_18 = rotl(w1_1[0], 18);
        uint32_t w1_0_19 = rotl(w1_1[0], 19);
        uint32_t w1_0_20 = rotl(w1_1[0], 20);
        uint32_t w1_0_21 = rotl(w1_1[0], 21);
        uint32_t w1_0_22 = rotl(w1_1[0], 22);

        uint32_t w1_0_6___w1_0_4 = w1_0_4 ^ w1_0_6;
        uint32_t w1_0_8___w1_0_4 = w1_0_4 ^ w1_0_8;
        uint32_t w1_0_8___w1_0_12 = w1_0_8 ^ w1_0_12; 
        uint32_t w1_0_6___w1_0_4___w1_0_7 = w1_0_4 ^ w1_0_6 ^ w1_0_7;     

        uint32_t w2_0_1 = rotl(w2_1[0], 1);
        uint32_t w2_0_2 = rotl(w2_1[0], 2);
        uint32_t w2_0_3 = rotl(w2_1[0], 3);
        uint32_t w2_0_4 = rotl(w2_1[0], 4);
        uint32_t w2_0_5 = rotl(w2_1[0], 5);
        uint32_t w2_0_6 = rotl(w2_1[0], 6);
        uint32_t w2_0_7 = rotl(w2_1[0], 7);
        uint32_t w2_0_8 = rotl(w2_1[0], 8);
        uint32_t w2_0_9 = rotl(w2_1[0], 9);
        uint32_t w2_0_10 = rotl(w2_1[0], 10);
        uint32_t w2_0_11 = rotl(w2_1[0], 11);
        uint32_t w2_0_12 = rotl(w2_1[0], 12);
        uint32_t w2_0_13 = rotl(w2_1[0], 13);
        uint32_t w2_0_14 = rotl(w2_1[0], 14);
        uint32_t w2_0_15 = rotl(w2_1[0], 15);
        uint32_t w2_0_16 = rotl(w2_1[0], 16);
        uint32_t w2_0_17 = rotl(w2_1[0], 17);
        uint32_t w2_0_18 = rotl(w2_1[0], 18);
        uint32_t w2_0_19 = rotl(w2_1[0], 19);
        uint32_t w2_0_20 = rotl(w2_1[0], 20);
        uint32_t w2_0_21 = rotl(w2_1[0], 21);
        uint32_t w2_0_22 = rotl(w2_1[0], 22);

        uint32_t w2_0_6___w2_0_4 = w2_0_4 ^ w2_0_6;
        uint32_t w2_0_8___w2_0_4 = w2_0_4 ^ w2_0_8;
        uint32_t w2_0_8___w2_0_12 = w2_0_8 ^ w2_0_12; 
        uint32_t w2_0_6___w2_0_4___w2_0_7 = w2_0_4 ^ w2_0_6 ^ w2_0_7;   

        uint32_t w3_0_1 = rotl(w3_1[0], 1);
        uint32_t w3_0_2 = rotl(w3_1[0], 2);
        uint32_t w3_0_3 = rotl(w3_1[0], 3);
        uint32_t w3_0_4 = rotl(w3_1[0], 4);
        uint32_t w3_0_5 = rotl(w3_1[0], 5);
        uint32_t w3_0_6 = rotl(w3_1[0], 6);
        uint32_t w3_0_7 = rotl(w3_1[0], 7);
        uint32_t w3_0_8 = rotl(w3_1[0], 8);
        uint32_t w3_0_9 = rotl(w3_1[0], 9);
        uint32_t w3_0_10 = rotl(w3_1[0], 10);
        uint32_t w3_0_11 = rotl(w3_1[0], 11);
        uint32_t w3_0_12 = rotl(w3_1[0], 12);
        uint32_t w3_0_13 = rotl(w3_1[0], 13);
        uint32_t w3_0_14 = rotl(w3_1[0], 14);
        uint32_t w3_0_15 = rotl(w3_1[0], 15);
        uint32_t w3_0_16 = rotl(w3_1[0], 16);
        uint32_t w3_0_17 = rotl(w3_1[0], 17);
        uint32_t w3_0_18 = rotl(w3_1[0], 18);
        uint32_t w3_0_19 = rotl(w3_1[0], 19);
        uint32_t w3_0_20 = rotl(w3_1[0], 20);
        uint32_t w3_0_21 = rotl(w3_1[0], 21);
        uint32_t w3_0_22 = rotl(w3_1[0], 22);

        uint32_t w3_0_6___w3_0_4 = w3_0_4 ^ w3_0_6;
        uint32_t w3_0_8___w3_0_4 = w3_0_4 ^ w3_0_8;
        uint32_t w3_0_8___w3_0_12 = w3_0_8 ^ w3_0_12; 
        uint32_t w3_0_6___w3_0_4___w3_0_7 = w3_0_4 ^ w3_0_6 ^ w3_0_7;   

        uint32_t w4_0_1 = rotl(w4_1[0], 1);
        uint32_t w4_0_2 = rotl(w4_1[0], 2);
        uint32_t w4_0_3 = rotl(w4_1[0], 3);
        uint32_t w4_0_4 = rotl(w4_1[0], 4);
        uint32_t w4_0_5 = rotl(w4_1[0], 5);
        uint32_t w4_0_6 = rotl(w4_1[0], 6);
        uint32_t w4_0_7 = rotl(w4_1[0], 7);
        uint32_t w4_0_8 = rotl(w4_1[0], 8);
        uint32_t w4_0_9 = rotl(w4_1[0], 9);
        uint32_t w4_0_10 = rotl(w4_1[0], 10);
        uint32_t w4_0_11 = rotl(w4_1[0], 11);
        uint32_t w4_0_12 = rotl(w4_1[0], 12);
        uint32_t w4_0_13 = rotl(w4_1[0], 13);
        uint32_t w4_0_14 = rotl(w4_1[0], 14);
        uint32_t w4_0_15 = rotl(w4_1[0], 15);
        uint32_t w4_0_16 = rotl(w4_1[0], 16);
        uint32_t w4_0_17 = rotl(w4_1[0], 17);
        uint32_t w4_0_18 = rotl(w4_1[0], 18);
        uint32_t w4_0_19 = rotl(w4_1[0], 19);
        uint32_t w4_0_20 = rotl(w4_1[0], 20);
        uint32_t w4_0_21 = rotl(w4_1[0], 21);
        uint32_t w4_0_22 = rotl(w4_1[0], 22);

        uint32_t w4_0_6___w4_0_4 = w4_0_4 ^ w4_0_6;
        uint32_t w4_0_8___w4_0_4 = w4_0_4 ^ w4_0_8;
        uint32_t w4_0_8___w4_0_12 = w4_0_8 ^ w4_0_12; 
        uint32_t w4_0_6___w4_0_4___w4_0_7 = w4_0_4 ^ w4_0_6 ^ w4_0_7;   

        //Check to see if we need to re-define PW[]'s and w[1] -- w[15]
        //------------------------------------------------------------
        //      PRE-PROSSES PASSWORD 1
        //------------------------------------------------------------
        //printf("w1_1[0] == 0x%x\n", w1_1[0]);
        if((w1_1[0] & 0xFF000000) == 0x61000000)
        {
            w1_1[1] = chunk1[1];
            w1_1[2] = chunk1[2];
            w1_1[3] = chunk1[3];
            w1_1[4] = chunk1[4];
            w1_1[5] = chunk1[5];
            w1_1[6] = chunk1[6];
            w1_1[7] = chunk1[7];
            w1_1[8] = chunk1[8];
            w1_1[9] = chunk1[9];
            w1_1[10] = chunk1[10];
            w1_1[11] = chunk1[11];
            w1_1[12] = chunk1[12];
            w1_1[13] = chunk1[13];
            w1_1[14] = chunk1[14];
            w1_1[15] = chunk1[15];

            PW[16] = rotl((w1_1[13] ^ w1_1[8] ^ w1_1[2]), 1);
            PW[17] = rotl((w1_1[14] ^ w1_1[9] ^ w1_1[3] ^ w1_1[1]), 1);
            PW[18] = rotl((w1_1[15] ^ w1_1[10] ^ w1_1[4] ^ w1_1[2]), 1);
            PW[19] = rotl((PW[16] ^ w1_1[11] ^ w1_1[5] ^ w1_1[3]), 1);
            PW[20] = rotl((PW[17] ^ w1_1[12] ^ w1_1[6] ^ w1_1[4]), 1);
            PW[21] = rotl((PW[18] ^ w1_1[13] ^ w1_1[7] ^ w1_1[5]), 1);
            PW[22] = rotl((PW[19] ^ w1_1[14] ^ w1_1[8] ^ w1_1[6]), 1);
            PW[23] = rotl((PW[20] ^ w1_1[15] ^ w1_1[9] ^ w1_1[7]), 1);
            PW[24] = rotl((PW[21] ^ PW[16] ^ w1_1[10] ^ w1_1[8]), 1);
            PW[25] = rotl((PW[22] ^ PW[17] ^ w1_1[11] ^ w1_1[9]), 1);
            PW[26] = rotl((PW[23] ^ PW[18] ^ w1_1[12] ^ w1_1[10]), 1);
            PW[27] = rotl((PW[24] ^ PW[19] ^ w1_1[13] ^ w1_1[11]), 1);
            PW[28] = rotl((PW[25] ^ PW[20] ^ w1_1[14] ^ w1_1[12]), 1);
            PW[29] = rotl((PW[26] ^ PW[21] ^ w1_1[15] ^ w1_1[13]), 1);
            PW[30] = rotl((PW[27] ^ PW[22] ^ PW[16] ^ w1_1[14]), 1);
            PW[31] = rotl((PW[28] ^ PW[23] ^ PW[17] ^ w1_1[15]), 1);
            PW[32] = rotl((PW[29] ^ PW[24] ^ PW[18] ^ PW[16]), 1);
            PW[33] = rotl((PW[30] ^ PW[25] ^ PW[19] ^ PW[17]), 1);
            PW[34] = rotl((PW[31] ^ PW[26] ^ PW[20] ^ PW[18]), 1);
            PW[35] = rotl((PW[32] ^ PW[27] ^ PW[21] ^ PW[19]), 1);
            PW[36] = rotl((PW[33] ^ PW[28] ^ PW[22] ^ PW[20]), 1);
            PW[37] = rotl((PW[34] ^ PW[29] ^ PW[23] ^ PW[21]), 1);
            PW[38] = rotl((PW[35] ^ PW[30] ^ PW[24] ^ PW[22]), 1);
            PW[39] = rotl((PW[36] ^ PW[31] ^ PW[25] ^ PW[23]), 1);
            PW[40] = rotl((PW[37] ^ PW[32] ^ PW[26] ^ PW[24]), 1);
            PW[41] = rotl((PW[38] ^ PW[33] ^ PW[27] ^ PW[25]), 1);
            PW[42] = rotl((PW[39] ^ PW[34] ^ PW[28] ^ PW[26]), 1);
            PW[43] = rotl((PW[40] ^ PW[35] ^ PW[29] ^ PW[27]), 1);
            PW[44] = rotl((PW[41] ^ PW[36] ^ PW[30] ^ PW[28]), 1);
            PW[45] = rotl((PW[42] ^ PW[37] ^ PW[31] ^ PW[29]), 1);
            PW[46] = rotl((PW[43] ^ PW[38] ^ PW[32] ^ PW[30]), 1);
            PW[47] = rotl((PW[44] ^ PW[39] ^ PW[33] ^ PW[31]), 1);
            PW[48] = rotl((PW[45] ^ PW[40] ^ PW[34] ^ PW[32]), 1);
            PW[49] = rotl((PW[46] ^ PW[41] ^ PW[35] ^ PW[33]), 1);
            PW[50] = rotl((PW[47] ^ PW[42] ^ PW[36] ^ PW[34]), 1);
            PW[51] = rotl((PW[48] ^ PW[43] ^ PW[37] ^ PW[35]), 1);
            PW[52] = rotl((PW[49] ^ PW[44] ^ PW[38] ^ PW[36]), 1);
            PW[53] = rotl((PW[50] ^ PW[45] ^ PW[39] ^ PW[37]), 1);
            PW[54] = rotl((PW[51] ^ PW[46] ^ PW[40] ^ PW[38]), 1);
            PW[55] = rotl((PW[52] ^ PW[47] ^ PW[41] ^ PW[39]), 1);
            PW[56] = rotl((PW[53] ^ PW[48] ^ PW[42] ^ PW[40]), 1);
            PW[57] = rotl((PW[54] ^ PW[49] ^ PW[43] ^ PW[41]), 1);
            PW[58] = rotl((PW[55] ^ PW[50] ^ PW[44] ^ PW[42]), 1);
            PW[59] = rotl((PW[56] ^ PW[51] ^ PW[45] ^ PW[43]), 1);
            PW[60] = rotl((PW[57] ^ PW[52] ^ PW[46] ^ PW[44]), 1);
            PW[61] = rotl((PW[58] ^ PW[53] ^ PW[47] ^ PW[45]), 1);
            PW[62] = rotl((PW[59] ^ PW[54] ^ PW[48] ^ PW[46]), 1);
            PW[63] = rotl((PW[60] ^ PW[55] ^ PW[49] ^ PW[47]), 1);
            PW[64] = rotl((PW[61] ^ PW[56] ^ PW[50] ^ PW[48]), 1);
            PW[65] = rotl((PW[62] ^ PW[57] ^ PW[51] ^ PW[49]), 1);
            PW[66] = rotl((PW[63] ^ PW[58] ^ PW[52] ^ PW[50]), 1);
            PW[67] = rotl((PW[64] ^ PW[59] ^ PW[53] ^ PW[51]), 1);
            PW[68] = rotl((PW[65] ^ PW[60] ^ PW[54] ^ PW[52]), 1);
            PW[69] = rotl((PW[66] ^ PW[61] ^ PW[55] ^ PW[53]), 1);
            PW[70] = rotl((PW[67] ^ PW[62] ^ PW[56] ^ PW[54]), 1);
            PW[71] = rotl((PW[68] ^ PW[63] ^ PW[57] ^ PW[55]), 1);
            PW[72] = rotl((PW[69] ^ PW[64] ^ PW[58] ^ PW[56]), 1);
            PW[73] = rotl((PW[70] ^ PW[65] ^ PW[59] ^ PW[57]), 1);
            PW[74] = rotl((PW[71] ^ PW[66] ^ PW[60] ^ PW[58]), 1);
            PW[75] = rotl((PW[72] ^ PW[67] ^ PW[61] ^ PW[59]), 1);
            PW[76] = rotl((PW[73] ^ PW[68] ^ PW[62] ^ PW[60]), 1);
            PW[77] = rotl((PW[74] ^ PW[69] ^ PW[63] ^ PW[61]), 1);
            PW[78] = rotl((PW[75] ^ PW[70] ^ PW[64] ^ PW[62]), 1);
            PW[79] = rotl((PW[76] ^ PW[71] ^ PW[65] ^ PW[63]), 1);


            //------------------------------------------------------------
            //      PRE-PROSSES PASSWORD 2
            //------------------------------------------------------------
            w2_1[1] = chunk2[1];
            w2_1[2] = chunk2[2];
            w2_1[3] = chunk2[3];
            w2_1[4] = chunk2[4];
            w2_1[5] = chunk2[5];
            w2_1[6] = chunk2[6];
            w2_1[7] = chunk2[7];
            w2_1[8] = chunk2[8];
            w2_1[9] = chunk2[9];
            w2_1[10] = chunk2[10];
            w2_1[11] = chunk2[11];
            w2_1[12] = chunk2[12];
            w2_1[13] = chunk2[13];
            w2_1[14] = chunk2[14];
            w2_1[15] = chunk2[15];

            /*PW[16] = rotl((w2_1[13] ^ w2_1[8] ^ w2_1[2]), 1);
            PW[17] = rotl((w2_1[14] ^ w2_1[9] ^ w2_1[3] ^ w2_1[1]), 1);
            PW[18] = rotl((w2_1[15] ^ w2_1[10] ^ w2_1[4] ^ w2_1[2]), 1);
            PW[19] = rotl((PW[16] ^ w2_1[11] ^ w2_1[5] ^ w2_1[3]), 1);
            PW[20] = rotl((PW[17] ^ w2_1[12] ^ w2_1[6] ^ w2_1[4]), 1);
            PW[21] = rotl((PW[18] ^ w2_1[13] ^ w2_1[7] ^ w2_1[5]), 1);
            PW[22] = rotl((PW[19] ^ w2_1[14] ^ w2_1[8] ^ w2_1[6]), 1);
            PW[23] = rotl((PW[20] ^ w2_1[15] ^ w2_1[9] ^ w2_1[7]), 1);
            PW[24] = rotl((PW[21] ^ PW[16] ^ w2_1[10] ^ w2_1[8]), 1);
            PW[25] = rotl((PW[22] ^ PW[17] ^ w2_1[11] ^ w2_1[9]), 1);
            PW[26] = rotl((PW[23] ^ PW[18] ^ w2_1[12] ^ w2_1[10]), 1);
            PW[27] = rotl((PW[24] ^ PW[19] ^ w2_1[13] ^ w2_1[11]), 1);
            PW[28] = rotl((PW[25] ^ PW[20] ^ w2_1[14] ^ w2_1[12]), 1);
            PW[29] = rotl((PW[26] ^ PW[21] ^ w2_1[15] ^ w2_1[13]), 1);
            PW[30] = rotl((PW[27] ^ PW[22] ^ PW[16] ^ w2_1[14]), 1);
            PW[31] = rotl((PW[28] ^ PW[23] ^ PW[17] ^ w2_1[15]), 1);
            PW[32] = rotl((PW[29] ^ PW[24] ^ PW[18] ^ PW[16]), 1);
            PW[33] = rotl((PW[30] ^ PW[25] ^ PW[19] ^ PW[17]), 1);
            PW[34] = rotl((PW[31] ^ PW[26] ^ PW[20] ^ PW[18]), 1);
            PW[35] = rotl((PW[32] ^ PW[27] ^ PW[21] ^ PW[19]), 1);
            PW[36] = rotl((PW[33] ^ PW[28] ^ PW[22] ^ PW[20]), 1);
            PW[37] = rotl((PW[34] ^ PW[29] ^ PW[23] ^ PW[21]), 1);
            PW[38] = rotl((PW[35] ^ PW[30] ^ PW[24] ^ PW[22]), 1);
            PW[39] = rotl((PW[36] ^ PW[31] ^ PW[25] ^ PW[23]), 1);
            PW[40] = rotl((PW[37] ^ PW[32] ^ PW[26] ^ PW[24]), 1);
            PW[41] = rotl((PW[38] ^ PW[33] ^ PW[27] ^ PW[25]), 1);
            PW[42] = rotl((PW[39] ^ PW[34] ^ PW[28] ^ PW[26]), 1);
            PW[43] = rotl((PW[40] ^ PW[35] ^ PW[29] ^ PW[27]), 1);
            PW[44] = rotl((PW[41] ^ PW[36] ^ PW[30] ^ PW[28]), 1);
            PW[45] = rotl((PW[42] ^ PW[37] ^ PW[31] ^ PW[29]), 1);
            PW[46] = rotl((PW[43] ^ PW[38] ^ PW[32] ^ PW[30]), 1);
            PW[47] = rotl((PW[44] ^ PW[39] ^ PW[33] ^ PW[31]), 1);
            PW[48] = rotl((PW[45] ^ PW[40] ^ PW[34] ^ PW[32]), 1);
            PW[49] = rotl((PW[46] ^ PW[41] ^ PW[35] ^ PW[33]), 1);
            PW[50] = rotl((PW[47] ^ PW[42] ^ PW[36] ^ PW[34]), 1);
            PW[51] = rotl((PW[48] ^ PW[43] ^ PW[37] ^ PW[35]), 1);
            PW[52] = rotl((PW[49] ^ PW[44] ^ PW[38] ^ PW[36]), 1);
            PW[53] = rotl((PW[50] ^ PW[45] ^ PW[39] ^ PW[37]), 1);
            PW[54] = rotl((PW[51] ^ PW[46] ^ PW[40] ^ PW[38]), 1);
            PW[55] = rotl((PW[52] ^ PW[47] ^ PW[41] ^ PW[39]), 1);
            PW[56] = rotl((PW[53] ^ PW[48] ^ PW[42] ^ PW[40]), 1);
            PW[57] = rotl((PW[54] ^ PW[49] ^ PW[43] ^ PW[41]), 1);
            PW[58] = rotl((PW[55] ^ PW[50] ^ PW[44] ^ PW[42]), 1);
            PW[59] = rotl((PW[56] ^ PW[51] ^ PW[45] ^ PW[43]), 1);
            PW[60] = rotl((PW[57] ^ PW[52] ^ PW[46] ^ PW[44]), 1);
            PW[61] = rotl((PW[58] ^ PW[53] ^ PW[47] ^ PW[45]), 1);
            PW[62] = rotl((PW[59] ^ PW[54] ^ PW[48] ^ PW[46]), 1);
            PW[63] = rotl((PW[60] ^ PW[55] ^ PW[49] ^ PW[47]), 1);
            PW[64] = rotl((PW[61] ^ PW[56] ^ PW[50] ^ PW[48]), 1);
            PW[65] = rotl((PW[62] ^ PW[57] ^ PW[51] ^ PW[49]), 1);
            PW[66] = rotl((PW[63] ^ PW[58] ^ PW[52] ^ PW[50]), 1);
            PW[67] = rotl((PW[64] ^ PW[59] ^ PW[53] ^ PW[51]), 1);
            PW[68] = rotl((PW[65] ^ PW[60] ^ PW[54] ^ PW[52]), 1);
            PW[69] = rotl((PW[66] ^ PW[61] ^ PW[55] ^ PW[53]), 1);
            PW[70] = rotl((PW[67] ^ PW[62] ^ PW[56] ^ PW[54]), 1);
            PW[71] = rotl((PW[68] ^ PW[63] ^ PW[57] ^ PW[55]), 1);
            PW[72] = rotl((PW[69] ^ PW[64] ^ PW[58] ^ PW[56]), 1);
            PW[73] = rotl((PW[70] ^ PW[65] ^ PW[59] ^ PW[57]), 1);
            PW[74] = rotl((PW[71] ^ PW[66] ^ PW[60] ^ PW[58]), 1);
            PW[75] = rotl((PW[72] ^ PW[67] ^ PW[61] ^ PW[59]), 1);
            PW[76] = rotl((PW[73] ^ PW[68] ^ PW[62] ^ PW[60]), 1);
            PW[77] = rotl((PW[74] ^ PW[69] ^ PW[63] ^ PW[61]), 1);
            PW[78] = rotl((PW[75] ^ PW[70] ^ PW[64] ^ PW[62]), 1);
            PW[79] = rotl((PW[76] ^ PW[71] ^ PW[65] ^ PW[63]), 1);*/


            //------------------------------------------------------------
            //      PRE-PROSSES PASSWORD 3
            //------------------------------------------------------------
            w3_1[1] = chunk3[1];
            w3_1[2] = chunk3[2];
            w3_1[3] = chunk3[3];
            w3_1[4] = chunk3[4];
            w3_1[5] = chunk3[5];
            w3_1[6] = chunk3[6];
            w3_1[7] = chunk3[7];
            w3_1[8] = chunk3[8];
            w3_1[9] = chunk3[9];
            w3_1[10] = chunk3[10];
            w3_1[11] = chunk3[11];
            w3_1[12] = chunk3[12];
            w3_1[13] = chunk3[13];
            w3_1[14] = chunk3[14];
            w3_1[15] = chunk3[15];

            /*PW[16] = rotl((w3_1[13] ^ w3_1[8] ^ w3_1[2]), 1);
            PW[17] = rotl((w3_1[14] ^ w3_1[9] ^ w3_1[3] ^ w3_1[1]), 1);
            PW[18] = rotl((w3_1[15] ^ w3_1[10] ^ w3_1[4] ^ w3_1[2]), 1);
            PW[19] = rotl((PW[16] ^ w3_1[11] ^ w3_1[5] ^ w3_1[3]), 1);
            PW[20] = rotl((PW[17] ^ w3_1[12] ^ w3_1[6] ^ w3_1[4]), 1);
            PW[21] = rotl((PW[18] ^ w3_1[13] ^ w3_1[7] ^ w3_1[5]), 1);
            PW[22] = rotl((PW[19] ^ w3_1[14] ^ w3_1[8] ^ w3_1[6]), 1);
            PW[23] = rotl((PW[20] ^ w3_1[15] ^ w3_1[9] ^ w3_1[7]), 1);
            PW[24] = rotl((PW[21] ^ PW[16] ^ w3_1[10] ^ w3_1[8]), 1);
            PW[25] = rotl((PW[22] ^ PW[17] ^ w3_1[11] ^ w3_1[9]), 1);
            PW[26] = rotl((PW[23] ^ PW[18] ^ w3_1[12] ^ w3_1[10]), 1);
            PW[27] = rotl((PW[24] ^ PW[19] ^ w3_1[13] ^ w3_1[11]), 1);
            PW[28] = rotl((PW[25] ^ PW[20] ^ w3_1[14] ^ w3_1[12]), 1);
            PW[29] = rotl((PW[26] ^ PW[21] ^ w3_1[15] ^ w3_1[13]), 1);
            PW[30] = rotl((PW[27] ^ PW[22] ^ PW[16] ^ w3_1[14]), 1);
            PW[31] = rotl((PW[28] ^ PW[23] ^ PW[17] ^ w3_1[15]), 1);
            PW[32] = rotl((PW[29] ^ PW[24] ^ PW[18] ^ PW[16]), 1);
            PW[33] = rotl((PW[30] ^ PW[25] ^ PW[19] ^ PW[17]), 1);
            PW[34] = rotl((PW[31] ^ PW[26] ^ PW[20] ^ PW[18]), 1);
            PW[35] = rotl((PW[32] ^ PW[27] ^ PW[21] ^ PW[19]), 1);
            PW[36] = rotl((PW[33] ^ PW[28] ^ PW[22] ^ PW[20]), 1);
            PW[37] = rotl((PW[34] ^ PW[29] ^ PW[23] ^ PW[21]), 1);
            PW[38] = rotl((PW[35] ^ PW[30] ^ PW[24] ^ PW[22]), 1);
            PW[39] = rotl((PW[36] ^ PW[31] ^ PW[25] ^ PW[23]), 1);
            PW[40] = rotl((PW[37] ^ PW[32] ^ PW[26] ^ PW[24]), 1);
            PW[41] = rotl((PW[38] ^ PW[33] ^ PW[27] ^ PW[25]), 1);
            PW[42] = rotl((PW[39] ^ PW[34] ^ PW[28] ^ PW[26]), 1);
            PW[43] = rotl((PW[40] ^ PW[35] ^ PW[29] ^ PW[27]), 1);
            PW[44] = rotl((PW[41] ^ PW[36] ^ PW[30] ^ PW[28]), 1);
            PW[45] = rotl((PW[42] ^ PW[37] ^ PW[31] ^ PW[29]), 1);
            PW[46] = rotl((PW[43] ^ PW[38] ^ PW[32] ^ PW[30]), 1);
            PW[47] = rotl((PW[44] ^ PW[39] ^ PW[33] ^ PW[31]), 1);
            PW[48] = rotl((PW[45] ^ PW[40] ^ PW[34] ^ PW[32]), 1);
            PW[49] = rotl((PW[46] ^ PW[41] ^ PW[35] ^ PW[33]), 1);
            PW[50] = rotl((PW[47] ^ PW[42] ^ PW[36] ^ PW[34]), 1);
            PW[51] = rotl((PW[48] ^ PW[43] ^ PW[37] ^ PW[35]), 1);
            PW[52] = rotl((PW[49] ^ PW[44] ^ PW[38] ^ PW[36]), 1);
            PW[53] = rotl((PW[50] ^ PW[45] ^ PW[39] ^ PW[37]), 1);
            PW[54] = rotl((PW[51] ^ PW[46] ^ PW[40] ^ PW[38]), 1);
            PW[55] = rotl((PW[52] ^ PW[47] ^ PW[41] ^ PW[39]), 1);
            PW[56] = rotl((PW[53] ^ PW[48] ^ PW[42] ^ PW[40]), 1);
            PW[57] = rotl((PW[54] ^ PW[49] ^ PW[43] ^ PW[41]), 1);
            PW[58] = rotl((PW[55] ^ PW[50] ^ PW[44] ^ PW[42]), 1);
            PW[59] = rotl((PW[56] ^ PW[51] ^ PW[45] ^ PW[43]), 1);
            PW[60] = rotl((PW[57] ^ PW[52] ^ PW[46] ^ PW[44]), 1);
            PW[61] = rotl((PW[58] ^ PW[53] ^ PW[47] ^ PW[45]), 1);
            PW[62] = rotl((PW[59] ^ PW[54] ^ PW[48] ^ PW[46]), 1);
            PW[63] = rotl((PW[60] ^ PW[55] ^ PW[49] ^ PW[47]), 1);
            PW[64] = rotl((PW[61] ^ PW[56] ^ PW[50] ^ PW[48]), 1);
            PW[65] = rotl((PW[62] ^ PW[57] ^ PW[51] ^ PW[49]), 1);
            PW[66] = rotl((PW[63] ^ PW[58] ^ PW[52] ^ PW[50]), 1);
            PW[67] = rotl((PW[64] ^ PW[59] ^ PW[53] ^ PW[51]), 1);
            PW[68] = rotl((PW[65] ^ PW[60] ^ PW[54] ^ PW[52]), 1);
            PW[69] = rotl((PW[66] ^ PW[61] ^ PW[55] ^ PW[53]), 1);
            PW[70] = rotl((PW[67] ^ PW[62] ^ PW[56] ^ PW[54]), 1);
            PW[71] = rotl((PW[68] ^ PW[63] ^ PW[57] ^ PW[55]), 1);
            PW[72] = rotl((PW[69] ^ PW[64] ^ PW[58] ^ PW[56]), 1);
            PW[73] = rotl((PW[70] ^ PW[65] ^ PW[59] ^ PW[57]), 1);
            PW[74] = rotl((PW[71] ^ PW[66] ^ PW[60] ^ PW[58]), 1);
            PW[75] = rotl((PW[72] ^ PW[67] ^ PW[61] ^ PW[59]), 1);
            PW[76] = rotl((PW[73] ^ PW[68] ^ PW[62] ^ PW[60]), 1);
            PW[77] = rotl((PW[74] ^ PW[69] ^ PW[63] ^ PW[61]), 1);
            PW[78] = rotl((PW[75] ^ PW[70] ^ PW[64] ^ PW[62]), 1);
            PW[79] = rotl((PW[76] ^ PW[71] ^ PW[65] ^ PW[63]), 1);*/


            //------------------------------------------------------------
            //      PRE-PROSSES PASSWORD 4
            //------------------------------------------------------------
            w4_1[1] = chunk4[1];
            w4_1[2] = chunk4[2];
            w4_1[3] = chunk4[3];
            w4_1[4] = chunk4[4];
            w4_1[5] = chunk4[5];
            w4_1[6] = chunk4[6];
            w4_1[7] = chunk4[7];
            w4_1[8] = chunk4[8];
            w4_1[9] = chunk4[9];
            w4_1[10] = chunk4[10];
            w4_1[11] = chunk4[11];
            w4_1[12] = chunk4[12];
            w4_1[13] = chunk4[13];
            w4_1[14] = chunk4[14];
            w4_1[15] = chunk4[15];

            /*PW[16] = rotl((w4_1[13] ^ w4_1[8] ^ w4_1[2]), 1);
            PW[17] = rotl((w4_1[14] ^ w4_1[9] ^ w4_1[3] ^ w4_1[1]), 1);
            PW[18] = rotl((w4_1[15] ^ w4_1[10] ^ w4_1[4] ^ w4_1[2]), 1);
            PW[19] = rotl((PW[16] ^ w4_1[11] ^ w4_1[5] ^ w4_1[3]), 1);
            PW[20] = rotl((PW[17] ^ w4_1[12] ^ w4_1[6] ^ w4_1[4]), 1);
            PW[21] = rotl((PW[18] ^ w4_1[13] ^ w4_1[7] ^ w4_1[5]), 1);
            PW[22] = rotl((PW[19] ^ w4_1[14] ^ w4_1[8] ^ w4_1[6]), 1);
            PW[23] = rotl((PW[20] ^ w4_1[15] ^ w4_1[9] ^ w4_1[7]), 1);
            PW[24] = rotl((PW[21] ^ PW[16] ^ w4_1[10] ^ w4_1[8]), 1);
            PW[25] = rotl((PW[22] ^ PW[17] ^ w4_1[11] ^ w4_1[9]), 1);
            PW[26] = rotl((PW[23] ^ PW[18] ^ w4_1[12] ^ w4_1[10]), 1);
            PW[27] = rotl((PW[24] ^ PW[19] ^ w4_1[13] ^ w4_1[11]), 1);
            PW[28] = rotl((PW[25] ^ PW[20] ^ w4_1[14] ^ w4_1[12]), 1);
            PW[29] = rotl((PW[26] ^ PW[21] ^ w4_1[15] ^ w4_1[13]), 1);
            PW[30] = rotl((PW[27] ^ PW[22] ^ PW[16] ^ w4_1[14]), 1);
            PW[31] = rotl((PW[28] ^ PW[23] ^ PW[17] ^ w4_1[15]), 1);
            PW[32] = rotl((PW[29] ^ PW[24] ^ PW[18] ^ PW[16]), 1);
            PW[33] = rotl((PW[30] ^ PW[25] ^ PW[19] ^ PW[17]), 1);
            PW[34] = rotl((PW[31] ^ PW[26] ^ PW[20] ^ PW[18]), 1);
            PW[35] = rotl((PW[32] ^ PW[27] ^ PW[21] ^ PW[19]), 1);
            PW[36] = rotl((PW[33] ^ PW[28] ^ PW[22] ^ PW[20]), 1);
            PW[37] = rotl((PW[34] ^ PW[29] ^ PW[23] ^ PW[21]), 1);
            PW[38] = rotl((PW[35] ^ PW[30] ^ PW[24] ^ PW[22]), 1);
            PW[39] = rotl((PW[36] ^ PW[31] ^ PW[25] ^ PW[23]), 1);
            PW[40] = rotl((PW[37] ^ PW[32] ^ PW[26] ^ PW[24]), 1);
            PW[41] = rotl((PW[38] ^ PW[33] ^ PW[27] ^ PW[25]), 1);
            PW[42] = rotl((PW[39] ^ PW[34] ^ PW[28] ^ PW[26]), 1);
            PW[43] = rotl((PW[40] ^ PW[35] ^ PW[29] ^ PW[27]), 1);
            PW[44] = rotl((PW[41] ^ PW[36] ^ PW[30] ^ PW[28]), 1);
            PW[45] = rotl((PW[42] ^ PW[37] ^ PW[31] ^ PW[29]), 1);
            PW[46] = rotl((PW[43] ^ PW[38] ^ PW[32] ^ PW[30]), 1);
            PW[47] = rotl((PW[44] ^ PW[39] ^ PW[33] ^ PW[31]), 1);
            PW[48] = rotl((PW[45] ^ PW[40] ^ PW[34] ^ PW[32]), 1);
            PW[49] = rotl((PW[46] ^ PW[41] ^ PW[35] ^ PW[33]), 1);
            PW[50] = rotl((PW[47] ^ PW[42] ^ PW[36] ^ PW[34]), 1);
            PW[51] = rotl((PW[48] ^ PW[43] ^ PW[37] ^ PW[35]), 1);
            PW[52] = rotl((PW[49] ^ PW[44] ^ PW[38] ^ PW[36]), 1);
            PW[53] = rotl((PW[50] ^ PW[45] ^ PW[39] ^ PW[37]), 1);
            PW[54] = rotl((PW[51] ^ PW[46] ^ PW[40] ^ PW[38]), 1);
            PW[55] = rotl((PW[52] ^ PW[47] ^ PW[41] ^ PW[39]), 1);
            PW[56] = rotl((PW[53] ^ PW[48] ^ PW[42] ^ PW[40]), 1);
            PW[57] = rotl((PW[54] ^ PW[49] ^ PW[43] ^ PW[41]), 1);
            PW[58] = rotl((PW[55] ^ PW[50] ^ PW[44] ^ PW[42]), 1);
            PW[59] = rotl((PW[56] ^ PW[51] ^ PW[45] ^ PW[43]), 1);
            PW[60] = rotl((PW[57] ^ PW[52] ^ PW[46] ^ PW[44]), 1);
            PW[61] = rotl((PW[58] ^ PW[53] ^ PW[47] ^ PW[45]), 1);
            PW[62] = rotl((PW[59] ^ PW[54] ^ PW[48] ^ PW[46]), 1);
            PW[63] = rotl((PW[60] ^ PW[55] ^ PW[49] ^ PW[47]), 1);
            PW[64] = rotl((PW[61] ^ PW[56] ^ PW[50] ^ PW[48]), 1);
            PW[65] = rotl((PW[62] ^ PW[57] ^ PW[51] ^ PW[49]), 1);
            PW[66] = rotl((PW[63] ^ PW[58] ^ PW[52] ^ PW[50]), 1);
            PW[67] = rotl((PW[64] ^ PW[59] ^ PW[53] ^ PW[51]), 1);
            PW[68] = rotl((PW[65] ^ PW[60] ^ PW[54] ^ PW[52]), 1);
            PW[69] = rotl((PW[66] ^ PW[61] ^ PW[55] ^ PW[53]), 1);
            PW[70] = rotl((PW[67] ^ PW[62] ^ PW[56] ^ PW[54]), 1);
            PW[71] = rotl((PW[68] ^ PW[63] ^ PW[57] ^ PW[55]), 1);
            PW[72] = rotl((PW[69] ^ PW[64] ^ PW[58] ^ PW[56]), 1);
            PW[73] = rotl((PW[70] ^ PW[65] ^ PW[59] ^ PW[57]), 1);
            PW[74] = rotl((PW[71] ^ PW[66] ^ PW[60] ^ PW[58]), 1);
            PW[75] = rotl((PW[72] ^ PW[67] ^ PW[61] ^ PW[59]), 1);
            PW[76] = rotl((PW[73] ^ PW[68] ^ PW[62] ^ PW[60]), 1);
            PW[77] = rotl((PW[74] ^ PW[69] ^ PW[63] ^ PW[61]), 1);
            PW[78] = rotl((PW[75] ^ PW[70] ^ PW[64] ^ PW[62]), 1);
            PW[79] = rotl((PW[76] ^ PW[71] ^ PW[65] ^ PW[63]), 1);*/
        }

        //------------------------------------------------------------
        //      OPTIMIZED OPERATIONS
        //------------------------------------------------------------
        // Extend the 16 32-bit words into 80 32-bit words w1
        w1_1[16] = PW[16] ^ w1_0_1;
        w1_1[17] = PW[17];
        w1_1[18] = PW[18];
        w1_1[19] = PW[19] ^ w1_0_2;
        w1_1[20] = PW[20];
        w1_1[21] = PW[21];
        w1_1[22] = PW[22] ^ w1_0_3;
        w1_1[23] = PW[23];
        w1_1[24] = PW[24] ^ w1_0_2;
        w1_1[25] = PW[25] ^ w1_0_4;
        w1_1[26] = PW[26];
        w1_1[27] = PW[27];
        w1_1[28] = PW[28] ^ w1_0_5;
        w1_1[29] = PW[29];
        w1_1[30] = PW[30] ^ w1_0_4 ^ w1_0_2;
        w1_1[31] = PW[31] ^ w1_0_6;
        w1_1[32] = PW[32] ^ w1_0_3 ^ w1_0_2;
        w1_1[33] = PW[33];
        w1_1[34] = PW[34] ^ w1_0_7;
        w1_1[35] = PW[35] ^ w1_0_4;
        w1_1[36] = PW[36] ^ w1_0_6___w1_0_4;
        w1_1[37] = PW[37] ^ w1_0_8;
        w1_1[38] = PW[38] ^ w1_0_4;
        w1_1[39] = PW[39];
        w1_1[40] = PW[40] ^ w1_0_4 ^ w1_0_9;
        w1_1[41] = PW[41];
        w1_1[42] = PW[42] ^ w1_0_6 ^ w1_0_8;
        w1_1[43] = PW[43] ^ w1_0_10;
        w1_1[44] = PW[44] ^ w1_0_6 ^ w1_0_3 ^ w1_0_7;
        w1_1[45] = PW[45];
        w1_1[46] = PW[46] ^ w1_0_4 ^ w1_0_11;
        w1_1[47] = PW[47] ^ w1_0_8___w1_0_4;
        w1_1[48] = PW[48] ^ w1_0_8___w1_0_4 ^ w1_0_3 ^ w1_0_10 ^ w1_0_5;
        w1_1[49] = PW[49] ^ w1_0_12;
        w1_1[50] = PW[50] ^ w1_0_8;
        w1_1[51] = PW[51] ^ w1_0_6___w1_0_4;
        w1_1[52] = PW[52] ^ w1_0_8___w1_0_4 ^ w1_0_13;
        w1_1[53] = PW[53];
        w1_1[54] = PW[54] ^ w1_0_7 ^ w1_0_10 ^ w1_0_12;
        w1_1[55] = PW[55] ^ w1_0_14;
        w1_1[56] = PW[56] ^ w1_0_6___w1_0_4___w1_0_7 ^ w1_0_11 ^ w1_0_10;
        w1_1[57] = PW[57] ^ w1_0_8;
        w1_1[58] = PW[58] ^ w1_0_8___w1_0_4 ^ w1_0_15;
        w1_1[59] = PW[59] ^ w1_0_8___w1_0_12;
        w1_1[60] = PW[60] ^ w1_0_8___w1_0_12 ^ w1_0_4 ^ w1_0_7 ^ w1_0_14;
        w1_1[61] = PW[61] ^ w1_0_16;
        w1_1[62] = PW[62] ^ w1_0_6___w1_0_4 ^ w1_0_8___w1_0_12;
        w1_1[63] = PW[63] ^ w1_0_8;
        w1_1[64] = PW[64] ^ w1_0_6___w1_0_4___w1_0_7 ^ w1_0_8___w1_0_12 ^ w1_0_17;
        w1_1[65] = PW[65];
        w1_1[66] = PW[66] ^ w1_0_14 ^ w1_0_16;
        w1_1[67] = PW[67] ^ w1_0_8 ^ w1_0_18;
        w1_1[68] = PW[68] ^ w1_0_11 ^ w1_0_14 ^ w1_0_15;
        w1_1[69] = PW[69];
        w1_1[70] = PW[70] ^ w1_0_12 ^ w1_0_19;
        w1_1[71] = PW[71] ^ w1_0_12 ^ w1_0_16;
        w1_1[72] = PW[72] ^ w1_0_11 ^ w1_0_12 ^ w1_0_18 ^ w1_0_13 ^ w1_0_16 ^ w1_0_5;
        w1_1[73] = PW[73] ^ w1_0_20;
        w1_1[74] = PW[74] ^ w1_0_8 ^ w1_0_16;
        w1_1[75] = PW[75] ^ w1_0_6 ^ w1_0_12 ^ w1_0_14;

        w1_1[76] = PW[76] ^ w1_0_7 ^ w1_0_8___w1_0_12 ^ w1_0_16 ^ w1_0_21;
        w1_1[77] = PW[77];
        w1_1[78] = PW[78] ^ w1_0_7 ^ w1_0_8 ^ w1_0_15 ^ w1_0_18 ^ w1_0_20;
        w1_1[79] = PW[79] ^ w1_0_8 ^ w1_0_22;

        // for(i = 0; i < 80; i++){
        //     printf("w1_1[%d] : %8X\n", i, w1_1[i]);
        // }


        // PW[76] = rotl((w1_1[73] ^ w1_1[68] ^ w1_1[62] ^ w1_1[60]), 1);
        //     ^ w1_0_20;                                      |REMOVE         ^ w1_0_6   |+1 to all|-->   
        //     ^ w1_0_11 ^ w1_0_14 ^ w1_0_15;                      REPEATS|--> ^ w1_0_7
        //     ^ w1_0_6___w1_0_4 ^ w1_0_8___w1_0_12;                           ^ w1_0_11
        //     ^ w1_0_8___w1_0_12 ^ w1_0_4 ^ w1_0_7 ^ w1_0_14;                 ^ w1_0_15
        //                                                                     ^ w1_0_20                                                                  

        // PW[77] = rotl((w1_1[74] ^ w1_1[69] ^ w1_1[63] ^ w1_1[61]), 1);
        //     ^ w1_0_8 ^ w1_0_16;     |REMOVE             
        //     ^ w1_0_8;                   REPEATS|-->
        //     ^ w1_0_16;

        // PW[78] = rotl((w1_1[75] ^ w1_1[70] ^ w1_1[64] ^ w1_1[62]), 1);
        //    ^ w1_0_6 ^ w1_0_12 ^ w1_0_14;                            |REMOVE         ^ w1_0_6    |+1 to all|-->
        //    ^ w1_0_12 ^ w1_0_19;                                         REPEATS|--> ^ w1_0_7
        //    ^ w1_0_6___w1_0_4___w1_0_7 ^ w1_0_8___w1_0_12 ^ w1_0_17;                 ^ w1_0_14
        //    ^ w1_0_6___w1_0_4 ^ w1_0_8___w1_0_12;                                    ^ w1_0_17
        //                                                                             ^ w1_0_19

        // PW[79] = rotl((w1_1[76] ^ w1_1[71] ^ w1_1[65] ^ w1_1[63]), 1);
        //     ^ w1_0_7 ^ w1_0_8 ^ w1_0_12 ^ w1_0_16 ^ w1_0_21; |REMOVE         ^ w1_0_7    |+1 to all|-->
        //     ^ w1_0_12 ^ w1_0_16;                                 REPEATS|--> ^ w1_0_21
        //     ^ w1_0_8;

        // Extend the 16 32-bit words into 80 32-bit words w2
        w2_1[16] = PW[16] ^ w2_0_1;
        w2_1[17] = PW[17];
        w2_1[18] = PW[18];
        w2_1[19] = PW[19] ^ w2_0_2;
        w2_1[20] = PW[20];
        w2_1[21] = PW[21];
        w2_1[22] = PW[22] ^ w2_0_3;
        w2_1[23] = PW[23];
        w2_1[24] = PW[24] ^ w2_0_2;
        w2_1[25] = PW[25] ^ w2_0_4;
        w2_1[26] = PW[26];
        w2_1[27] = PW[27];
        w2_1[28] = PW[28] ^ w2_0_5;
        w2_1[29] = PW[29];
        w2_1[30] = PW[30] ^ w2_0_4 ^ w2_0_2;
        w2_1[31] = PW[31] ^ w2_0_6;
        w2_1[32] = PW[32] ^ w2_0_3 ^ w2_0_2;
        w2_1[33] = PW[33];
        w2_1[34] = PW[34] ^ w2_0_7;
        w2_1[35] = PW[35] ^ w2_0_4;
        w2_1[36] = PW[36] ^ w2_0_6___w2_0_4;
        w2_1[37] = PW[37] ^ w2_0_8;
        w2_1[38] = PW[38] ^ w2_0_4;
        w2_1[39] = PW[39];
        w2_1[40] = PW[40] ^ w2_0_4 ^ w2_0_9;
        w2_1[41] = PW[41];
        w2_1[42] = PW[42] ^ w2_0_6 ^ w2_0_8;
        w2_1[43] = PW[43] ^ w2_0_10;
        w2_1[44] = PW[44] ^ w2_0_6 ^ w2_0_3 ^ w2_0_7;
        w2_1[45] = PW[45];
        w2_1[46] = PW[46] ^ w2_0_4 ^ w2_0_11;
        w2_1[47] = PW[47] ^ w2_0_8___w2_0_4;
        w2_1[48] = PW[48] ^ w2_0_8___w2_0_4 ^ w2_0_3 ^ w2_0_10 ^ w2_0_5;
        w2_1[49] = PW[49] ^ w2_0_12;
        w2_1[50] = PW[50] ^ w2_0_8;
        w2_1[51] = PW[51] ^ w2_0_6___w2_0_4;
        w2_1[52] = PW[52] ^ w2_0_8___w2_0_4 ^ w2_0_13;
        w2_1[53] = PW[53];
        w2_1[54] = PW[54] ^ w2_0_7 ^ w2_0_10 ^ w2_0_12;
        w2_1[55] = PW[55] ^ w2_0_14;
        w2_1[56] = PW[56] ^ w2_0_6___w2_0_4___w2_0_7 ^ w2_0_11 ^ w2_0_10;
        w2_1[57] = PW[57] ^ w2_0_8;
        w2_1[58] = PW[58] ^ w2_0_8___w2_0_4 ^ w2_0_15;
        w2_1[59] = PW[59] ^ w2_0_8___w2_0_12;
        w2_1[60] = PW[60] ^ w2_0_8___w2_0_12 ^ w2_0_4 ^ w2_0_7 ^ w2_0_14;
        w2_1[61] = PW[61] ^ w2_0_16;
        w2_1[62] = PW[62] ^ w2_0_6___w2_0_4 ^ w2_0_8___w2_0_12;
        w2_1[63] = PW[63] ^ w2_0_8;
        w2_1[64] = PW[64] ^ w2_0_6___w2_0_4___w2_0_7 ^ w2_0_8___w2_0_12 ^ w2_0_17;
        w2_1[65] = PW[65];
        w2_1[66] = PW[66] ^ w2_0_14 ^ w2_0_16;
        w2_1[67] = PW[67] ^ w2_0_8 ^ w2_0_18;
        w2_1[68] = PW[68] ^ w2_0_11 ^ w2_0_14 ^ w2_0_15;
        w2_1[69] = PW[69];
        w2_1[70] = PW[70] ^ w2_0_12 ^ w2_0_19;
        w2_1[71] = PW[71] ^ w2_0_12 ^ w2_0_16;
        w2_1[72] = PW[72] ^ w2_0_11 ^ w2_0_12 ^ w2_0_18 ^ w2_0_13 ^ w2_0_16 ^ w2_0_5;
        w2_1[73] = PW[73] ^ w2_0_20;
        w2_1[74] = PW[74] ^ w2_0_8 ^ w2_0_16;
        w2_1[75] = PW[75] ^ w2_0_6 ^ w2_0_12 ^ w2_0_14;

        w2_1[76] = PW[76] ^ w2_0_7 ^ w2_0_8___w2_0_12 ^ w2_0_16 ^ w2_0_21;
        w2_1[77] = PW[77];
        w2_1[78] = PW[78] ^ w2_0_7 ^ w2_0_8 ^ w2_0_15 ^ w2_0_18 ^ w2_0_20;
        w2_1[79] = PW[79] ^ w2_0_8 ^ w2_0_22;   

        
        // Extend the 16 32-bit words into 80 32-bit words w3
        w3_1[16] = PW[16] ^ w3_0_1;
        w3_1[17] = PW[17];
        w3_1[18] = PW[18];
        w3_1[19] = PW[19] ^ w3_0_2;
        w3_1[20] = PW[20];
        w3_1[21] = PW[21];
        w3_1[22] = PW[22] ^ w3_0_3;
        w3_1[23] = PW[23];
        w3_1[24] = PW[24] ^ w3_0_2;
        w3_1[25] = PW[25] ^ w3_0_4;
        w3_1[26] = PW[26];
        w3_1[27] = PW[27];
        w3_1[28] = PW[28] ^ w3_0_5;
        w3_1[29] = PW[29];
        w3_1[30] = PW[30] ^ w3_0_4 ^ w3_0_2;
        w3_1[31] = PW[31] ^ w3_0_6;
        w3_1[32] = PW[32] ^ w3_0_3 ^ w3_0_2;
        w3_1[33] = PW[33];
        w3_1[34] = PW[34] ^ w3_0_7;
        w3_1[35] = PW[35] ^ w3_0_4;
        w3_1[36] = PW[36] ^ w3_0_6___w3_0_4;
        w3_1[37] = PW[37] ^ w3_0_8;
        w3_1[38] = PW[38] ^ w3_0_4;
        w3_1[39] = PW[39];
        w3_1[40] = PW[40] ^ w3_0_4 ^ w3_0_9;
        w3_1[41] = PW[41];
        w3_1[42] = PW[42] ^ w3_0_6 ^ w3_0_8;
        w3_1[43] = PW[43] ^ w3_0_10;
        w3_1[44] = PW[44] ^ w3_0_6 ^ w3_0_3 ^ w3_0_7;
        w3_1[45] = PW[45];
        w3_1[46] = PW[46] ^ w3_0_4 ^ w3_0_11;
        w3_1[47] = PW[47] ^ w3_0_8___w3_0_4;
        w3_1[48] = PW[48] ^ w3_0_8___w3_0_4 ^ w3_0_3 ^ w3_0_10 ^ w3_0_5;
        w3_1[49] = PW[49] ^ w3_0_12;
        w3_1[50] = PW[50] ^ w3_0_8;
        w3_1[51] = PW[51] ^ w3_0_6___w3_0_4;
        w3_1[52] = PW[52] ^ w3_0_8___w3_0_4 ^ w3_0_13;
        w3_1[53] = PW[53];
        w3_1[54] = PW[54] ^ w3_0_7 ^ w3_0_10 ^ w3_0_12;
        w3_1[55] = PW[55] ^ w3_0_14;
        w3_1[56] = PW[56] ^ w3_0_6___w3_0_4___w3_0_7 ^ w3_0_11 ^ w3_0_10;
        w3_1[57] = PW[57] ^ w3_0_8;
        w3_1[58] = PW[58] ^ w3_0_8___w3_0_4 ^ w3_0_15;
        w3_1[59] = PW[59] ^ w3_0_8___w3_0_12;
        w3_1[60] = PW[60] ^ w3_0_8___w3_0_12 ^ w3_0_4 ^ w3_0_7 ^ w3_0_14;
        w3_1[61] = PW[61] ^ w3_0_16;
        w3_1[62] = PW[62] ^ w3_0_6___w3_0_4 ^ w3_0_8___w3_0_12;
        w3_1[63] = PW[63] ^ w3_0_8;
        w3_1[64] = PW[64] ^ w3_0_6___w3_0_4___w3_0_7 ^ w3_0_8___w3_0_12 ^ w3_0_17;
        w3_1[65] = PW[65];
        w3_1[66] = PW[66] ^ w3_0_14 ^ w3_0_16;
        w3_1[67] = PW[67] ^ w3_0_8 ^ w3_0_18;
        w3_1[68] = PW[68] ^ w3_0_11 ^ w3_0_14 ^ w3_0_15;
        w3_1[69] = PW[69];
        w3_1[70] = PW[70] ^ w3_0_12 ^ w3_0_19;
        w3_1[71] = PW[71] ^ w3_0_12 ^ w3_0_16;
        w3_1[72] = PW[72] ^ w3_0_11 ^ w3_0_12 ^ w3_0_18 ^ w3_0_13 ^ w3_0_16 ^ w3_0_5;
        w3_1[73] = PW[73] ^ w3_0_20;
        w3_1[74] = PW[74] ^ w3_0_8 ^ w3_0_16;
        w3_1[75] = PW[75] ^ w3_0_6 ^ w3_0_12 ^ w3_0_14;

        w3_1[76] = PW[76] ^ w3_0_7 ^ w3_0_8___w3_0_12 ^ w3_0_16 ^ w3_0_21;
        w3_1[77] = PW[77];
        w3_1[78] = PW[78] ^ w3_0_7 ^ w3_0_8 ^ w3_0_15 ^ w3_0_18 ^ w3_0_20;
        w3_1[79] = PW[79] ^ w3_0_8 ^ w3_0_22;


        // Extend the 16 32-bit words into 80 32-bit words w4
        w4_1[16] = PW[16] ^ w4_0_1;
        w4_1[17] = PW[17];
        w4_1[18] = PW[18];
        w4_1[19] = PW[19] ^ w4_0_2;
        w4_1[20] = PW[20];
        w4_1[21] = PW[21];
        w4_1[22] = PW[22] ^ w4_0_3;
        w4_1[23] = PW[23];
        w4_1[24] = PW[24] ^ w4_0_2;
        w4_1[25] = PW[25] ^ w4_0_4;
        w4_1[26] = PW[26];
        w4_1[27] = PW[27];
        w4_1[28] = PW[28] ^ w4_0_5;
        w4_1[29] = PW[29];
        w4_1[30] = PW[30] ^ w4_0_4 ^ w4_0_2;
        w4_1[31] = PW[31] ^ w4_0_6;
        w4_1[32] = PW[32] ^ w4_0_3 ^ w4_0_2;
        w4_1[33] = PW[33];
        w4_1[34] = PW[34] ^ w4_0_7;
        w4_1[35] = PW[35] ^ w4_0_4;
        w4_1[36] = PW[36] ^ w4_0_6___w4_0_4;
        w4_1[37] = PW[37] ^ w4_0_8;
        w4_1[38] = PW[38] ^ w4_0_4;
        w4_1[39] = PW[39];
        w4_1[40] = PW[40] ^ w4_0_4 ^ w4_0_9;
        w4_1[41] = PW[41];
        w4_1[42] = PW[42] ^ w4_0_6 ^ w4_0_8;
        w4_1[43] = PW[43] ^ w4_0_10;
        w4_1[44] = PW[44] ^ w4_0_6 ^ w4_0_3 ^ w4_0_7;
        w4_1[45] = PW[45];
        w4_1[46] = PW[46] ^ w4_0_4 ^ w4_0_11;
        w4_1[47] = PW[47] ^ w4_0_8___w4_0_4;
        w4_1[48] = PW[48] ^ w4_0_8___w4_0_4 ^ w4_0_3 ^ w4_0_10 ^ w4_0_5;
        w4_1[49] = PW[49] ^ w4_0_12;
        w4_1[50] = PW[50] ^ w4_0_8;
        w4_1[51] = PW[51] ^ w4_0_6___w4_0_4;
        w4_1[52] = PW[52] ^ w4_0_8___w4_0_4 ^ w4_0_13;
        w4_1[53] = PW[53];
        w4_1[54] = PW[54] ^ w4_0_7 ^ w4_0_10 ^ w4_0_12;
        w4_1[55] = PW[55] ^ w4_0_14;
        w4_1[56] = PW[56] ^ w4_0_6___w4_0_4___w4_0_7 ^ w4_0_11 ^ w4_0_10;
        w4_1[57] = PW[57] ^ w4_0_8;
        w4_1[58] = PW[58] ^ w4_0_8___w4_0_4 ^ w4_0_15;
        w4_1[59] = PW[59] ^ w4_0_8___w4_0_12;
        w4_1[60] = PW[60] ^ w4_0_8___w4_0_12 ^ w4_0_4 ^ w4_0_7 ^ w4_0_14;
        w4_1[61] = PW[61] ^ w4_0_16;
        w4_1[62] = PW[62] ^ w4_0_6___w4_0_4 ^ w4_0_8___w4_0_12;
        w4_1[63] = PW[63] ^ w4_0_8;
        w4_1[64] = PW[64] ^ w4_0_6___w4_0_4___w4_0_7 ^ w4_0_8___w4_0_12 ^ w4_0_17;
        w4_1[65] = PW[65];
        w4_1[66] = PW[66] ^ w4_0_14 ^ w4_0_16;
        w4_1[67] = PW[67] ^ w4_0_8 ^ w4_0_18;
        w4_1[68] = PW[68] ^ w4_0_11 ^ w4_0_14 ^ w4_0_15;
        w4_1[69] = PW[69];
        w4_1[70] = PW[70] ^ w4_0_12 ^ w4_0_19;
        w4_1[71] = PW[71] ^ w4_0_12 ^ w4_0_16;
        w4_1[72] = PW[72] ^ w4_0_11 ^ w4_0_12 ^ w4_0_18 ^ w4_0_13 ^ w4_0_16 ^ w4_0_5;
        w4_1[73] = PW[73] ^ w4_0_20;
        w4_1[74] = PW[74] ^ w4_0_8 ^ w4_0_16;
        w4_1[75] = PW[75] ^ w4_0_6 ^ w4_0_12 ^ w4_0_14;

        w4_1[76] = PW[76] ^ w4_0_7 ^ w4_0_8___w4_0_12 ^ w4_0_16 ^ w4_0_21;
        w4_1[77] = PW[77];
        w4_1[78] = PW[78] ^ w4_0_7 ^ w4_0_8 ^ w4_0_15 ^ w4_0_18 ^ w4_0_20;
        w4_1[79] = PW[79] ^ w4_0_8 ^ w4_0_22;

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
        __m128i vecTemp = temp(vecA, vecE, vecF, k, w1_1[0], w2_1[0], w3_1[0], w4_1[0]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[1], w2_1[1], w3_1[1], w4_1[1]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[2], w2_1[2], w3_1[2], w4_1[2]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[3], w2_1[3], w3_1[3], w4_1[3]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[4], w2_1[4], w3_1[4], w4_1[4]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[5], w2_1[5], w3_1[5], w4_1[5]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[6], w2_1[6], w3_1[6], w4_1[6]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[7], w2_1[7], w3_1[7], w4_1[7]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[8], w2_1[8], w3_1[8], w4_1[8]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[9], w2_1[9], w3_1[9], w4_1[9]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[10], w2_1[10], w3_1[10], w4_1[10]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[11], w2_1[11], w3_1[11], w4_1[11]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[12], w2_1[12], w3_1[12], w4_1[12]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[13], w2_1[13], w3_1[13], w4_1[13]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[14], w2_1[14], w3_1[14], w4_1[14]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[15], w2_1[15], w3_1[15], w4_1[15]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[16], w2_1[16], w3_1[16], w4_1[16]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[17], w2_1[17], w3_1[17], w4_1[17]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[18], w2_1[18], w3_1[18], w4_1[18]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[19], w2_1[19], w3_1[19], w4_1[19]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        // -----------------------------------------

        k = 0x6ED9EBA1;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[20], w2_1[20], w3_1[20], w4_1[20]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[21], w2_1[21], w3_1[21], w4_1[21]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[22], w2_1[22], w3_1[22], w4_1[22]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[23], w2_1[23], w3_1[23], w4_1[23]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[24], w2_1[24], w3_1[24], w4_1[24]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[25], w2_1[25], w3_1[25], w4_1[25]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[26], w2_1[26], w3_1[26], w4_1[26]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[27], w2_1[27], w3_1[27], w4_1[27]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[28], w2_1[28], w3_1[28], w4_1[28]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[29], w2_1[29], w3_1[29], w4_1[29]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[30], w2_1[30], w3_1[30], w4_1[30]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[31], w2_1[31], w3_1[31], w4_1[31]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[32], w2_1[32], w3_1[32], w4_1[32]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[33], w2_1[33], w3_1[33], w4_1[33]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[34], w2_1[34], w3_1[34], w4_1[34]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[35], w2_1[35], w3_1[35], w4_1[35]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[36], w2_1[36], w3_1[36], w4_1[36]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[37], w2_1[37], w3_1[37], w4_1[37]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[38], w2_1[38], w3_1[38], w4_1[38]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[39], w2_1[39], w3_1[39], w4_1[39]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        // -----------------------

        k = 0x8F1BBCDC;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[40], w2_1[40], w3_1[40], w4_1[40]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[41], w2_1[41], w3_1[41], w4_1[41]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[42], w2_1[42], w3_1[42], w4_1[42]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[43], w2_1[43], w3_1[43], w4_1[43]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[44], w2_1[44], w3_1[44], w4_1[44]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[45], w2_1[45], w3_1[45], w4_1[45]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[46], w2_1[46], w3_1[46], w4_1[46]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[47], w2_1[47], w3_1[47], w4_1[47]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[48], w2_1[48], w3_1[48], w4_1[48]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[49], w2_1[49], w3_1[49], w4_1[49]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[50], w2_1[50], w3_1[50], w4_1[50]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[51], w2_1[51], w3_1[51], w4_1[51]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[52], w2_1[52], w3_1[52], w4_1[52]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[53], w2_1[53], w3_1[53], w4_1[53]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[54], w2_1[54], w3_1[54], w4_1[54]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[55], w2_1[55], w3_1[55], w4_1[55]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[56], w2_1[56], w3_1[56], w4_1[56]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[57], w2_1[57], w3_1[57], w4_1[57]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[58], w2_1[58], w3_1[58], w4_1[58]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[59], w2_1[59], w3_1[59], w4_1[59]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        // ------------------------------------

        k = 0xCA62C1D6;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[60], w2_1[60], w3_1[60], w4_1[60]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[61], w2_1[61], w3_1[61], w4_1[61]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[62], w2_1[62], w3_1[62], w4_1[62]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[63], w2_1[63], w3_1[63], w4_1[63]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[64], w2_1[64], w3_1[64], w4_1[64]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[65], w2_1[65], w3_1[65], w4_1[65]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[66], w2_1[66], w3_1[66], w4_1[66]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[67], w2_1[67], w3_1[67], w4_1[67]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[68], w2_1[68], w3_1[68], w4_1[68]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[69], w2_1[69], w3_1[69], w4_1[69]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[70], w2_1[70], w3_1[70], w4_1[70]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[71], w2_1[71], w3_1[71], w4_1[71]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[72], w2_1[72], w3_1[72], w4_1[72]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[73], w2_1[73], w3_1[73], w4_1[73]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[74], w2_1[74], w3_1[74], w4_1[74]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[75], w2_1[75], w3_1[75], w4_1[75]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[76], w2_1[76], w3_1[76], w4_1[76]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[77], w2_1[77], w3_1[77], w4_1[77]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[78], w2_1[78], w3_1[78], w4_1[78]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_1[79], w2_1[79], w3_1[79], w4_1[79]);
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
    if(thread_number == 1)
    {
        //Define w1[0], w2[0], w3[0], w4[0]
        w1_2[0] = chunk1[0];
        w2_2[0] = chunk2[0];
        w3_2[0] = chunk3[0];
        w4_2[0] = chunk4[0];

        uint32_t w1_0_1 = rotl(w1_2[0], 1);
        uint32_t w1_0_2 = rotl(w1_2[0], 2);
        uint32_t w1_0_3 = rotl(w1_2[0], 3);
        uint32_t w1_0_4 = rotl(w1_2[0], 4);
        uint32_t w1_0_5 = rotl(w1_2[0], 5);
        uint32_t w1_0_6 = rotl(w1_2[0], 6);
        uint32_t w1_0_7 = rotl(w1_2[0], 7);
        uint32_t w1_0_8 = rotl(w1_2[0], 8);
        uint32_t w1_0_9 = rotl(w1_2[0], 9);
        uint32_t w1_0_10 = rotl(w1_2[0], 10);
        uint32_t w1_0_11 = rotl(w1_2[0], 11);
        uint32_t w1_0_12 = rotl(w1_2[0], 12);
        uint32_t w1_0_13 = rotl(w1_2[0], 13);
        uint32_t w1_0_14 = rotl(w1_2[0], 14);
        uint32_t w1_0_15 = rotl(w1_2[0], 15);
        uint32_t w1_0_16 = rotl(w1_2[0], 16);
        uint32_t w1_0_17 = rotl(w1_2[0], 17);
        uint32_t w1_0_18 = rotl(w1_2[0], 18);
        uint32_t w1_0_19 = rotl(w1_2[0], 19);
        uint32_t w1_0_20 = rotl(w1_2[0], 20);
        uint32_t w1_0_21 = rotl(w1_2[0], 21);
        uint32_t w1_0_22 = rotl(w1_2[0], 22);

        uint32_t w1_0_6___w1_0_4 = w1_0_4 ^ w1_0_6;
        uint32_t w1_0_8___w1_0_4 = w1_0_4 ^ w1_0_8;
        uint32_t w1_0_8___w1_0_12 = w1_0_8 ^ w1_0_12; 
        uint32_t w1_0_6___w1_0_4___w1_0_7 = w1_0_4 ^ w1_0_6 ^ w1_0_7;     

        uint32_t w2_0_1 = rotl(w2_2[0], 1);
        uint32_t w2_0_2 = rotl(w2_2[0], 2);
        uint32_t w2_0_3 = rotl(w2_2[0], 3);
        uint32_t w2_0_4 = rotl(w2_2[0], 4);
        uint32_t w2_0_5 = rotl(w2_2[0], 5);
        uint32_t w2_0_6 = rotl(w2_2[0], 6);
        uint32_t w2_0_7 = rotl(w2_2[0], 7);
        uint32_t w2_0_8 = rotl(w2_2[0], 8);
        uint32_t w2_0_9 = rotl(w2_2[0], 9);
        uint32_t w2_0_10 = rotl(w2_2[0], 10);
        uint32_t w2_0_11 = rotl(w2_2[0], 11);
        uint32_t w2_0_12 = rotl(w2_2[0], 12);
        uint32_t w2_0_13 = rotl(w2_2[0], 13);
        uint32_t w2_0_14 = rotl(w2_2[0], 14);
        uint32_t w2_0_15 = rotl(w2_2[0], 15);
        uint32_t w2_0_16 = rotl(w2_2[0], 16);
        uint32_t w2_0_17 = rotl(w2_2[0], 17);
        uint32_t w2_0_18 = rotl(w2_2[0], 18);
        uint32_t w2_0_19 = rotl(w2_2[0], 19);
        uint32_t w2_0_20 = rotl(w2_2[0], 20);
        uint32_t w2_0_21 = rotl(w2_2[0], 21);
        uint32_t w2_0_22 = rotl(w2_2[0], 22);

        uint32_t w2_0_6___w2_0_4 = w2_0_4 ^ w2_0_6;
        uint32_t w2_0_8___w2_0_4 = w2_0_4 ^ w2_0_8;
        uint32_t w2_0_8___w2_0_12 = w2_0_8 ^ w2_0_12; 
        uint32_t w2_0_6___w2_0_4___w2_0_7 = w2_0_4 ^ w2_0_6 ^ w2_0_7;   

        uint32_t w3_0_1 = rotl(w3_2[0], 1);
        uint32_t w3_0_2 = rotl(w3_2[0], 2);
        uint32_t w3_0_3 = rotl(w3_2[0], 3);
        uint32_t w3_0_4 = rotl(w3_2[0], 4);
        uint32_t w3_0_5 = rotl(w3_2[0], 5);
        uint32_t w3_0_6 = rotl(w3_2[0], 6);
        uint32_t w3_0_7 = rotl(w3_2[0], 7);
        uint32_t w3_0_8 = rotl(w3_2[0], 8);
        uint32_t w3_0_9 = rotl(w3_2[0], 9);
        uint32_t w3_0_10 = rotl(w3_2[0], 10);
        uint32_t w3_0_11 = rotl(w3_2[0], 11);
        uint32_t w3_0_12 = rotl(w3_2[0], 12);
        uint32_t w3_0_13 = rotl(w3_2[0], 13);
        uint32_t w3_0_14 = rotl(w3_2[0], 14);
        uint32_t w3_0_15 = rotl(w3_2[0], 15);
        uint32_t w3_0_16 = rotl(w3_2[0], 16);
        uint32_t w3_0_17 = rotl(w3_2[0], 17);
        uint32_t w3_0_18 = rotl(w3_2[0], 18);
        uint32_t w3_0_19 = rotl(w3_2[0], 19);
        uint32_t w3_0_20 = rotl(w3_2[0], 20);
        uint32_t w3_0_21 = rotl(w3_2[0], 21);
        uint32_t w3_0_22 = rotl(w3_2[0], 22);

        uint32_t w3_0_6___w3_0_4 = w3_0_4 ^ w3_0_6;
        uint32_t w3_0_8___w3_0_4 = w3_0_4 ^ w3_0_8;
        uint32_t w3_0_8___w3_0_12 = w3_0_8 ^ w3_0_12; 
        uint32_t w3_0_6___w3_0_4___w3_0_7 = w3_0_4 ^ w3_0_6 ^ w3_0_7;   

        uint32_t w4_0_1 = rotl(w4_2[0], 1);
        uint32_t w4_0_2 = rotl(w4_2[0], 2);
        uint32_t w4_0_3 = rotl(w4_2[0], 3);
        uint32_t w4_0_4 = rotl(w4_2[0], 4);
        uint32_t w4_0_5 = rotl(w4_2[0], 5);
        uint32_t w4_0_6 = rotl(w4_2[0], 6);
        uint32_t w4_0_7 = rotl(w4_2[0], 7);
        uint32_t w4_0_8 = rotl(w4_2[0], 8);
        uint32_t w4_0_9 = rotl(w4_2[0], 9);
        uint32_t w4_0_10 = rotl(w4_2[0], 10);
        uint32_t w4_0_11 = rotl(w4_2[0], 11);
        uint32_t w4_0_12 = rotl(w4_2[0], 12);
        uint32_t w4_0_13 = rotl(w4_2[0], 13);
        uint32_t w4_0_14 = rotl(w4_2[0], 14);
        uint32_t w4_0_15 = rotl(w4_2[0], 15);
        uint32_t w4_0_16 = rotl(w4_2[0], 16);
        uint32_t w4_0_17 = rotl(w4_2[0], 17);
        uint32_t w4_0_18 = rotl(w4_2[0], 18);
        uint32_t w4_0_19 = rotl(w4_2[0], 19);
        uint32_t w4_0_20 = rotl(w4_2[0], 20);
        uint32_t w4_0_21 = rotl(w4_2[0], 21);
        uint32_t w4_0_22 = rotl(w4_2[0], 22);

        uint32_t w4_0_6___w4_0_4 = w4_0_4 ^ w4_0_6;
        uint32_t w4_0_8___w4_0_4 = w4_0_4 ^ w4_0_8;
        uint32_t w4_0_8___w4_0_12 = w4_0_8 ^ w4_0_12; 
        uint32_t w4_0_6___w4_0_4___w4_0_7 = w4_0_4 ^ w4_0_6 ^ w4_0_7;   

        //Check to see if we need to re-define PW[]'s and w[1] -- w[15]
        //------------------------------------------------------------
        //      PRE-PROSSES PASSWORD 1
        //------------------------------------------------------------
        //printf("w1_2[0] == 0x%x\n", w1_2[0]);
        if((w1_2[0] & 0xFF000000) == 0x61000000)
        {
            w1_2[1] = chunk1[1];
            w1_2[2] = chunk1[2];
            w1_2[3] = chunk1[3];
            w1_2[4] = chunk1[4];
            w1_2[5] = chunk1[5];
            w1_2[6] = chunk1[6];
            w1_2[7] = chunk1[7];
            w1_2[8] = chunk1[8];
            w1_2[9] = chunk1[9];
            w1_2[10] = chunk1[10];
            w1_2[11] = chunk1[11];
            w1_2[12] = chunk1[12];
            w1_2[13] = chunk1[13];
            w1_2[14] = chunk1[14];
            w1_2[15] = chunk1[15];

            PW[16] = rotl((w1_2[13] ^ w1_2[8] ^ w1_2[2]), 1);
            PW[17] = rotl((w1_2[14] ^ w1_2[9] ^ w1_2[3] ^ w1_2[1]), 1);
            PW[18] = rotl((w1_2[15] ^ w1_2[10] ^ w1_2[4] ^ w1_2[2]), 1);
            PW[19] = rotl((PW[16] ^ w1_2[11] ^ w1_2[5] ^ w1_2[3]), 1);
            PW[20] = rotl((PW[17] ^ w1_2[12] ^ w1_2[6] ^ w1_2[4]), 1);
            PW[21] = rotl((PW[18] ^ w1_2[13] ^ w1_2[7] ^ w1_2[5]), 1);
            PW[22] = rotl((PW[19] ^ w1_2[14] ^ w1_2[8] ^ w1_2[6]), 1);
            PW[23] = rotl((PW[20] ^ w1_2[15] ^ w1_2[9] ^ w1_2[7]), 1);
            PW[24] = rotl((PW[21] ^ PW[16] ^ w1_2[10] ^ w1_2[8]), 1);
            PW[25] = rotl((PW[22] ^ PW[17] ^ w1_2[11] ^ w1_2[9]), 1);
            PW[26] = rotl((PW[23] ^ PW[18] ^ w1_2[12] ^ w1_2[10]), 1);
            PW[27] = rotl((PW[24] ^ PW[19] ^ w1_2[13] ^ w1_2[11]), 1);
            PW[28] = rotl((PW[25] ^ PW[20] ^ w1_2[14] ^ w1_2[12]), 1);
            PW[29] = rotl((PW[26] ^ PW[21] ^ w1_2[15] ^ w1_2[13]), 1);
            PW[30] = rotl((PW[27] ^ PW[22] ^ PW[16] ^ w1_2[14]), 1);
            PW[31] = rotl((PW[28] ^ PW[23] ^ PW[17] ^ w1_2[15]), 1);
            PW[32] = rotl((PW[29] ^ PW[24] ^ PW[18] ^ PW[16]), 1);
            PW[33] = rotl((PW[30] ^ PW[25] ^ PW[19] ^ PW[17]), 1);
            PW[34] = rotl((PW[31] ^ PW[26] ^ PW[20] ^ PW[18]), 1);
            PW[35] = rotl((PW[32] ^ PW[27] ^ PW[21] ^ PW[19]), 1);
            PW[36] = rotl((PW[33] ^ PW[28] ^ PW[22] ^ PW[20]), 1);
            PW[37] = rotl((PW[34] ^ PW[29] ^ PW[23] ^ PW[21]), 1);
            PW[38] = rotl((PW[35] ^ PW[30] ^ PW[24] ^ PW[22]), 1);
            PW[39] = rotl((PW[36] ^ PW[31] ^ PW[25] ^ PW[23]), 1);
            PW[40] = rotl((PW[37] ^ PW[32] ^ PW[26] ^ PW[24]), 1);
            PW[41] = rotl((PW[38] ^ PW[33] ^ PW[27] ^ PW[25]), 1);
            PW[42] = rotl((PW[39] ^ PW[34] ^ PW[28] ^ PW[26]), 1);
            PW[43] = rotl((PW[40] ^ PW[35] ^ PW[29] ^ PW[27]), 1);
            PW[44] = rotl((PW[41] ^ PW[36] ^ PW[30] ^ PW[28]), 1);
            PW[45] = rotl((PW[42] ^ PW[37] ^ PW[31] ^ PW[29]), 1);
            PW[46] = rotl((PW[43] ^ PW[38] ^ PW[32] ^ PW[30]), 1);
            PW[47] = rotl((PW[44] ^ PW[39] ^ PW[33] ^ PW[31]), 1);
            PW[48] = rotl((PW[45] ^ PW[40] ^ PW[34] ^ PW[32]), 1);
            PW[49] = rotl((PW[46] ^ PW[41] ^ PW[35] ^ PW[33]), 1);
            PW[50] = rotl((PW[47] ^ PW[42] ^ PW[36] ^ PW[34]), 1);
            PW[51] = rotl((PW[48] ^ PW[43] ^ PW[37] ^ PW[35]), 1);
            PW[52] = rotl((PW[49] ^ PW[44] ^ PW[38] ^ PW[36]), 1);
            PW[53] = rotl((PW[50] ^ PW[45] ^ PW[39] ^ PW[37]), 1);
            PW[54] = rotl((PW[51] ^ PW[46] ^ PW[40] ^ PW[38]), 1);
            PW[55] = rotl((PW[52] ^ PW[47] ^ PW[41] ^ PW[39]), 1);
            PW[56] = rotl((PW[53] ^ PW[48] ^ PW[42] ^ PW[40]), 1);
            PW[57] = rotl((PW[54] ^ PW[49] ^ PW[43] ^ PW[41]), 1);
            PW[58] = rotl((PW[55] ^ PW[50] ^ PW[44] ^ PW[42]), 1);
            PW[59] = rotl((PW[56] ^ PW[51] ^ PW[45] ^ PW[43]), 1);
            PW[60] = rotl((PW[57] ^ PW[52] ^ PW[46] ^ PW[44]), 1);
            PW[61] = rotl((PW[58] ^ PW[53] ^ PW[47] ^ PW[45]), 1);
            PW[62] = rotl((PW[59] ^ PW[54] ^ PW[48] ^ PW[46]), 1);
            PW[63] = rotl((PW[60] ^ PW[55] ^ PW[49] ^ PW[47]), 1);
            PW[64] = rotl((PW[61] ^ PW[56] ^ PW[50] ^ PW[48]), 1);
            PW[65] = rotl((PW[62] ^ PW[57] ^ PW[51] ^ PW[49]), 1);
            PW[66] = rotl((PW[63] ^ PW[58] ^ PW[52] ^ PW[50]), 1);
            PW[67] = rotl((PW[64] ^ PW[59] ^ PW[53] ^ PW[51]), 1);
            PW[68] = rotl((PW[65] ^ PW[60] ^ PW[54] ^ PW[52]), 1);
            PW[69] = rotl((PW[66] ^ PW[61] ^ PW[55] ^ PW[53]), 1);
            PW[70] = rotl((PW[67] ^ PW[62] ^ PW[56] ^ PW[54]), 1);
            PW[71] = rotl((PW[68] ^ PW[63] ^ PW[57] ^ PW[55]), 1);
            PW[72] = rotl((PW[69] ^ PW[64] ^ PW[58] ^ PW[56]), 1);
            PW[73] = rotl((PW[70] ^ PW[65] ^ PW[59] ^ PW[57]), 1);
            PW[74] = rotl((PW[71] ^ PW[66] ^ PW[60] ^ PW[58]), 1);
            PW[75] = rotl((PW[72] ^ PW[67] ^ PW[61] ^ PW[59]), 1);
            PW[76] = rotl((PW[73] ^ PW[68] ^ PW[62] ^ PW[60]), 1);
            PW[77] = rotl((PW[74] ^ PW[69] ^ PW[63] ^ PW[61]), 1);
            PW[78] = rotl((PW[75] ^ PW[70] ^ PW[64] ^ PW[62]), 1);
            PW[79] = rotl((PW[76] ^ PW[71] ^ PW[65] ^ PW[63]), 1);


            //------------------------------------------------------------
            //      PRE-PROSSES PASSWORD 2
            //------------------------------------------------------------
            w2_2[1] = chunk2[1];
            w2_2[2] = chunk2[2];
            w2_2[3] = chunk2[3];
            w2_2[4] = chunk2[4];
            w2_2[5] = chunk2[5];
            w2_2[6] = chunk2[6];
            w2_2[7] = chunk2[7];
            w2_2[8] = chunk2[8];
            w2_2[9] = chunk2[9];
            w2_2[10] = chunk2[10];
            w2_2[11] = chunk2[11];
            w2_2[12] = chunk2[12];
            w2_2[13] = chunk2[13];
            w2_2[14] = chunk2[14];
            w2_2[15] = chunk2[15];

            /*PW[16] = rotl((w2_2[13] ^ w2_2[8] ^ w2_2[2]), 1);
            PW[17] = rotl((w2_2[14] ^ w2_2[9] ^ w2_2[3] ^ w2_2[1]), 1);
            PW[18] = rotl((w2_2[15] ^ w2_2[10] ^ w2_2[4] ^ w2_2[2]), 1);
            PW[19] = rotl((PW[16] ^ w2_2[11] ^ w2_2[5] ^ w2_2[3]), 1);
            PW[20] = rotl((PW[17] ^ w2_2[12] ^ w2_2[6] ^ w2_2[4]), 1);
            PW[21] = rotl((PW[18] ^ w2_2[13] ^ w2_2[7] ^ w2_2[5]), 1);
            PW[22] = rotl((PW[19] ^ w2_2[14] ^ w2_2[8] ^ w2_2[6]), 1);
            PW[23] = rotl((PW[20] ^ w2_2[15] ^ w2_2[9] ^ w2_2[7]), 1);
            PW[24] = rotl((PW[21] ^ PW[16] ^ w2_2[10] ^ w2_2[8]), 1);
            PW[25] = rotl((PW[22] ^ PW[17] ^ w2_2[11] ^ w2_2[9]), 1);
            PW[26] = rotl((PW[23] ^ PW[18] ^ w2_2[12] ^ w2_2[10]), 1);
            PW[27] = rotl((PW[24] ^ PW[19] ^ w2_2[13] ^ w2_2[11]), 1);
            PW[28] = rotl((PW[25] ^ PW[20] ^ w2_2[14] ^ w2_2[12]), 1);
            PW[29] = rotl((PW[26] ^ PW[21] ^ w2_2[15] ^ w2_2[13]), 1);
            PW[30] = rotl((PW[27] ^ PW[22] ^ PW[16] ^ w2_2[14]), 1);
            PW[31] = rotl((PW[28] ^ PW[23] ^ PW[17] ^ w2_2[15]), 1);
            PW[32] = rotl((PW[29] ^ PW[24] ^ PW[18] ^ PW[16]), 1);
            PW[33] = rotl((PW[30] ^ PW[25] ^ PW[19] ^ PW[17]), 1);
            PW[34] = rotl((PW[31] ^ PW[26] ^ PW[20] ^ PW[18]), 1);
            PW[35] = rotl((PW[32] ^ PW[27] ^ PW[21] ^ PW[19]), 1);
            PW[36] = rotl((PW[33] ^ PW[28] ^ PW[22] ^ PW[20]), 1);
            PW[37] = rotl((PW[34] ^ PW[29] ^ PW[23] ^ PW[21]), 1);
            PW[38] = rotl((PW[35] ^ PW[30] ^ PW[24] ^ PW[22]), 1);
            PW[39] = rotl((PW[36] ^ PW[31] ^ PW[25] ^ PW[23]), 1);
            PW[40] = rotl((PW[37] ^ PW[32] ^ PW[26] ^ PW[24]), 1);
            PW[41] = rotl((PW[38] ^ PW[33] ^ PW[27] ^ PW[25]), 1);
            PW[42] = rotl((PW[39] ^ PW[34] ^ PW[28] ^ PW[26]), 1);
            PW[43] = rotl((PW[40] ^ PW[35] ^ PW[29] ^ PW[27]), 1);
            PW[44] = rotl((PW[41] ^ PW[36] ^ PW[30] ^ PW[28]), 1);
            PW[45] = rotl((PW[42] ^ PW[37] ^ PW[31] ^ PW[29]), 1);
            PW[46] = rotl((PW[43] ^ PW[38] ^ PW[32] ^ PW[30]), 1);
            PW[47] = rotl((PW[44] ^ PW[39] ^ PW[33] ^ PW[31]), 1);
            PW[48] = rotl((PW[45] ^ PW[40] ^ PW[34] ^ PW[32]), 1);
            PW[49] = rotl((PW[46] ^ PW[41] ^ PW[35] ^ PW[33]), 1);
            PW[50] = rotl((PW[47] ^ PW[42] ^ PW[36] ^ PW[34]), 1);
            PW[51] = rotl((PW[48] ^ PW[43] ^ PW[37] ^ PW[35]), 1);
            PW[52] = rotl((PW[49] ^ PW[44] ^ PW[38] ^ PW[36]), 1);
            PW[53] = rotl((PW[50] ^ PW[45] ^ PW[39] ^ PW[37]), 1);
            PW[54] = rotl((PW[51] ^ PW[46] ^ PW[40] ^ PW[38]), 1);
            PW[55] = rotl((PW[52] ^ PW[47] ^ PW[41] ^ PW[39]), 1);
            PW[56] = rotl((PW[53] ^ PW[48] ^ PW[42] ^ PW[40]), 1);
            PW[57] = rotl((PW[54] ^ PW[49] ^ PW[43] ^ PW[41]), 1);
            PW[58] = rotl((PW[55] ^ PW[50] ^ PW[44] ^ PW[42]), 1);
            PW[59] = rotl((PW[56] ^ PW[51] ^ PW[45] ^ PW[43]), 1);
            PW[60] = rotl((PW[57] ^ PW[52] ^ PW[46] ^ PW[44]), 1);
            PW[61] = rotl((PW[58] ^ PW[53] ^ PW[47] ^ PW[45]), 1);
            PW[62] = rotl((PW[59] ^ PW[54] ^ PW[48] ^ PW[46]), 1);
            PW[63] = rotl((PW[60] ^ PW[55] ^ PW[49] ^ PW[47]), 1);
            PW[64] = rotl((PW[61] ^ PW[56] ^ PW[50] ^ PW[48]), 1);
            PW[65] = rotl((PW[62] ^ PW[57] ^ PW[51] ^ PW[49]), 1);
            PW[66] = rotl((PW[63] ^ PW[58] ^ PW[52] ^ PW[50]), 1);
            PW[67] = rotl((PW[64] ^ PW[59] ^ PW[53] ^ PW[51]), 1);
            PW[68] = rotl((PW[65] ^ PW[60] ^ PW[54] ^ PW[52]), 1);
            PW[69] = rotl((PW[66] ^ PW[61] ^ PW[55] ^ PW[53]), 1);
            PW[70] = rotl((PW[67] ^ PW[62] ^ PW[56] ^ PW[54]), 1);
            PW[71] = rotl((PW[68] ^ PW[63] ^ PW[57] ^ PW[55]), 1);
            PW[72] = rotl((PW[69] ^ PW[64] ^ PW[58] ^ PW[56]), 1);
            PW[73] = rotl((PW[70] ^ PW[65] ^ PW[59] ^ PW[57]), 1);
            PW[74] = rotl((PW[71] ^ PW[66] ^ PW[60] ^ PW[58]), 1);
            PW[75] = rotl((PW[72] ^ PW[67] ^ PW[61] ^ PW[59]), 1);
            PW[76] = rotl((PW[73] ^ PW[68] ^ PW[62] ^ PW[60]), 1);
            PW[77] = rotl((PW[74] ^ PW[69] ^ PW[63] ^ PW[61]), 1);
            PW[78] = rotl((PW[75] ^ PW[70] ^ PW[64] ^ PW[62]), 1);
            PW[79] = rotl((PW[76] ^ PW[71] ^ PW[65] ^ PW[63]), 1);*/


            //------------------------------------------------------------
            //      PRE-PROSSES PASSWORD 3
            //------------------------------------------------------------
            w3_2[1] = chunk3[1];
            w3_2[2] = chunk3[2];
            w3_2[3] = chunk3[3];
            w3_2[4] = chunk3[4];
            w3_2[5] = chunk3[5];
            w3_2[6] = chunk3[6];
            w3_2[7] = chunk3[7];
            w3_2[8] = chunk3[8];
            w3_2[9] = chunk3[9];
            w3_2[10] = chunk3[10];
            w3_2[11] = chunk3[11];
            w3_2[12] = chunk3[12];
            w3_2[13] = chunk3[13];
            w3_2[14] = chunk3[14];
            w3_2[15] = chunk3[15];

            /*PW[16] = rotl((w3_2[13] ^ w3_2[8] ^ w3_2[2]), 1);
            PW[17] = rotl((w3_2[14] ^ w3_2[9] ^ w3_2[3] ^ w3_2[1]), 1);
            PW[18] = rotl((w3_2[15] ^ w3_2[10] ^ w3_2[4] ^ w3_2[2]), 1);
            PW[19] = rotl((PW[16] ^ w3_2[11] ^ w3_2[5] ^ w3_2[3]), 1);
            PW[20] = rotl((PW[17] ^ w3_2[12] ^ w3_2[6] ^ w3_2[4]), 1);
            PW[21] = rotl((PW[18] ^ w3_2[13] ^ w3_2[7] ^ w3_2[5]), 1);
            PW[22] = rotl((PW[19] ^ w3_2[14] ^ w3_2[8] ^ w3_2[6]), 1);
            PW[23] = rotl((PW[20] ^ w3_2[15] ^ w3_2[9] ^ w3_2[7]), 1);
            PW[24] = rotl((PW[21] ^ PW[16] ^ w3_2[10] ^ w3_2[8]), 1);
            PW[25] = rotl((PW[22] ^ PW[17] ^ w3_2[11] ^ w3_2[9]), 1);
            PW[26] = rotl((PW[23] ^ PW[18] ^ w3_2[12] ^ w3_2[10]), 1);
            PW[27] = rotl((PW[24] ^ PW[19] ^ w3_2[13] ^ w3_2[11]), 1);
            PW[28] = rotl((PW[25] ^ PW[20] ^ w3_2[14] ^ w3_2[12]), 1);
            PW[29] = rotl((PW[26] ^ PW[21] ^ w3_2[15] ^ w3_2[13]), 1);
            PW[30] = rotl((PW[27] ^ PW[22] ^ PW[16] ^ w3_2[14]), 1);
            PW[31] = rotl((PW[28] ^ PW[23] ^ PW[17] ^ w3_2[15]), 1);
            PW[32] = rotl((PW[29] ^ PW[24] ^ PW[18] ^ PW[16]), 1);
            PW[33] = rotl((PW[30] ^ PW[25] ^ PW[19] ^ PW[17]), 1);
            PW[34] = rotl((PW[31] ^ PW[26] ^ PW[20] ^ PW[18]), 1);
            PW[35] = rotl((PW[32] ^ PW[27] ^ PW[21] ^ PW[19]), 1);
            PW[36] = rotl((PW[33] ^ PW[28] ^ PW[22] ^ PW[20]), 1);
            PW[37] = rotl((PW[34] ^ PW[29] ^ PW[23] ^ PW[21]), 1);
            PW[38] = rotl((PW[35] ^ PW[30] ^ PW[24] ^ PW[22]), 1);
            PW[39] = rotl((PW[36] ^ PW[31] ^ PW[25] ^ PW[23]), 1);
            PW[40] = rotl((PW[37] ^ PW[32] ^ PW[26] ^ PW[24]), 1);
            PW[41] = rotl((PW[38] ^ PW[33] ^ PW[27] ^ PW[25]), 1);
            PW[42] = rotl((PW[39] ^ PW[34] ^ PW[28] ^ PW[26]), 1);
            PW[43] = rotl((PW[40] ^ PW[35] ^ PW[29] ^ PW[27]), 1);
            PW[44] = rotl((PW[41] ^ PW[36] ^ PW[30] ^ PW[28]), 1);
            PW[45] = rotl((PW[42] ^ PW[37] ^ PW[31] ^ PW[29]), 1);
            PW[46] = rotl((PW[43] ^ PW[38] ^ PW[32] ^ PW[30]), 1);
            PW[47] = rotl((PW[44] ^ PW[39] ^ PW[33] ^ PW[31]), 1);
            PW[48] = rotl((PW[45] ^ PW[40] ^ PW[34] ^ PW[32]), 1);
            PW[49] = rotl((PW[46] ^ PW[41] ^ PW[35] ^ PW[33]), 1);
            PW[50] = rotl((PW[47] ^ PW[42] ^ PW[36] ^ PW[34]), 1);
            PW[51] = rotl((PW[48] ^ PW[43] ^ PW[37] ^ PW[35]), 1);
            PW[52] = rotl((PW[49] ^ PW[44] ^ PW[38] ^ PW[36]), 1);
            PW[53] = rotl((PW[50] ^ PW[45] ^ PW[39] ^ PW[37]), 1);
            PW[54] = rotl((PW[51] ^ PW[46] ^ PW[40] ^ PW[38]), 1);
            PW[55] = rotl((PW[52] ^ PW[47] ^ PW[41] ^ PW[39]), 1);
            PW[56] = rotl((PW[53] ^ PW[48] ^ PW[42] ^ PW[40]), 1);
            PW[57] = rotl((PW[54] ^ PW[49] ^ PW[43] ^ PW[41]), 1);
            PW[58] = rotl((PW[55] ^ PW[50] ^ PW[44] ^ PW[42]), 1);
            PW[59] = rotl((PW[56] ^ PW[51] ^ PW[45] ^ PW[43]), 1);
            PW[60] = rotl((PW[57] ^ PW[52] ^ PW[46] ^ PW[44]), 1);
            PW[61] = rotl((PW[58] ^ PW[53] ^ PW[47] ^ PW[45]), 1);
            PW[62] = rotl((PW[59] ^ PW[54] ^ PW[48] ^ PW[46]), 1);
            PW[63] = rotl((PW[60] ^ PW[55] ^ PW[49] ^ PW[47]), 1);
            PW[64] = rotl((PW[61] ^ PW[56] ^ PW[50] ^ PW[48]), 1);
            PW[65] = rotl((PW[62] ^ PW[57] ^ PW[51] ^ PW[49]), 1);
            PW[66] = rotl((PW[63] ^ PW[58] ^ PW[52] ^ PW[50]), 1);
            PW[67] = rotl((PW[64] ^ PW[59] ^ PW[53] ^ PW[51]), 1);
            PW[68] = rotl((PW[65] ^ PW[60] ^ PW[54] ^ PW[52]), 1);
            PW[69] = rotl((PW[66] ^ PW[61] ^ PW[55] ^ PW[53]), 1);
            PW[70] = rotl((PW[67] ^ PW[62] ^ PW[56] ^ PW[54]), 1);
            PW[71] = rotl((PW[68] ^ PW[63] ^ PW[57] ^ PW[55]), 1);
            PW[72] = rotl((PW[69] ^ PW[64] ^ PW[58] ^ PW[56]), 1);
            PW[73] = rotl((PW[70] ^ PW[65] ^ PW[59] ^ PW[57]), 1);
            PW[74] = rotl((PW[71] ^ PW[66] ^ PW[60] ^ PW[58]), 1);
            PW[75] = rotl((PW[72] ^ PW[67] ^ PW[61] ^ PW[59]), 1);
            PW[76] = rotl((PW[73] ^ PW[68] ^ PW[62] ^ PW[60]), 1);
            PW[77] = rotl((PW[74] ^ PW[69] ^ PW[63] ^ PW[61]), 1);
            PW[78] = rotl((PW[75] ^ PW[70] ^ PW[64] ^ PW[62]), 1);
            PW[79] = rotl((PW[76] ^ PW[71] ^ PW[65] ^ PW[63]), 1);*/


            //------------------------------------------------------------
            //      PRE-PROSSES PASSWORD 4
            //------------------------------------------------------------
            w4_2[1] = chunk4[1];
            w4_2[2] = chunk4[2];
            w4_2[3] = chunk4[3];
            w4_2[4] = chunk4[4];
            w4_2[5] = chunk4[5];
            w4_2[6] = chunk4[6];
            w4_2[7] = chunk4[7];
            w4_2[8] = chunk4[8];
            w4_2[9] = chunk4[9];
            w4_2[10] = chunk4[10];
            w4_2[11] = chunk4[11];
            w4_2[12] = chunk4[12];
            w4_2[13] = chunk4[13];
            w4_2[14] = chunk4[14];
            w4_2[15] = chunk4[15];

            /*PW[16] = rotl((w4_2[13] ^ w4_2[8] ^ w4_2[2]), 1);
            PW[17] = rotl((w4_2[14] ^ w4_2[9] ^ w4_2[3] ^ w4_2[1]), 1);
            PW[18] = rotl((w4_2[15] ^ w4_2[10] ^ w4_2[4] ^ w4_2[2]), 1);
            PW[19] = rotl((PW[16] ^ w4_2[11] ^ w4_2[5] ^ w4_2[3]), 1);
            PW[20] = rotl((PW[17] ^ w4_2[12] ^ w4_2[6] ^ w4_2[4]), 1);
            PW[21] = rotl((PW[18] ^ w4_2[13] ^ w4_2[7] ^ w4_2[5]), 1);
            PW[22] = rotl((PW[19] ^ w4_2[14] ^ w4_2[8] ^ w4_2[6]), 1);
            PW[23] = rotl((PW[20] ^ w4_2[15] ^ w4_2[9] ^ w4_2[7]), 1);
            PW[24] = rotl((PW[21] ^ PW[16] ^ w4_2[10] ^ w4_2[8]), 1);
            PW[25] = rotl((PW[22] ^ PW[17] ^ w4_2[11] ^ w4_2[9]), 1);
            PW[26] = rotl((PW[23] ^ PW[18] ^ w4_2[12] ^ w4_2[10]), 1);
            PW[27] = rotl((PW[24] ^ PW[19] ^ w4_2[13] ^ w4_2[11]), 1);
            PW[28] = rotl((PW[25] ^ PW[20] ^ w4_2[14] ^ w4_2[12]), 1);
            PW[29] = rotl((PW[26] ^ PW[21] ^ w4_2[15] ^ w4_2[13]), 1);
            PW[30] = rotl((PW[27] ^ PW[22] ^ PW[16] ^ w4_2[14]), 1);
            PW[31] = rotl((PW[28] ^ PW[23] ^ PW[17] ^ w4_2[15]), 1);
            PW[32] = rotl((PW[29] ^ PW[24] ^ PW[18] ^ PW[16]), 1);
            PW[33] = rotl((PW[30] ^ PW[25] ^ PW[19] ^ PW[17]), 1);
            PW[34] = rotl((PW[31] ^ PW[26] ^ PW[20] ^ PW[18]), 1);
            PW[35] = rotl((PW[32] ^ PW[27] ^ PW[21] ^ PW[19]), 1);
            PW[36] = rotl((PW[33] ^ PW[28] ^ PW[22] ^ PW[20]), 1);
            PW[37] = rotl((PW[34] ^ PW[29] ^ PW[23] ^ PW[21]), 1);
            PW[38] = rotl((PW[35] ^ PW[30] ^ PW[24] ^ PW[22]), 1);
            PW[39] = rotl((PW[36] ^ PW[31] ^ PW[25] ^ PW[23]), 1);
            PW[40] = rotl((PW[37] ^ PW[32] ^ PW[26] ^ PW[24]), 1);
            PW[41] = rotl((PW[38] ^ PW[33] ^ PW[27] ^ PW[25]), 1);
            PW[42] = rotl((PW[39] ^ PW[34] ^ PW[28] ^ PW[26]), 1);
            PW[43] = rotl((PW[40] ^ PW[35] ^ PW[29] ^ PW[27]), 1);
            PW[44] = rotl((PW[41] ^ PW[36] ^ PW[30] ^ PW[28]), 1);
            PW[45] = rotl((PW[42] ^ PW[37] ^ PW[31] ^ PW[29]), 1);
            PW[46] = rotl((PW[43] ^ PW[38] ^ PW[32] ^ PW[30]), 1);
            PW[47] = rotl((PW[44] ^ PW[39] ^ PW[33] ^ PW[31]), 1);
            PW[48] = rotl((PW[45] ^ PW[40] ^ PW[34] ^ PW[32]), 1);
            PW[49] = rotl((PW[46] ^ PW[41] ^ PW[35] ^ PW[33]), 1);
            PW[50] = rotl((PW[47] ^ PW[42] ^ PW[36] ^ PW[34]), 1);
            PW[51] = rotl((PW[48] ^ PW[43] ^ PW[37] ^ PW[35]), 1);
            PW[52] = rotl((PW[49] ^ PW[44] ^ PW[38] ^ PW[36]), 1);
            PW[53] = rotl((PW[50] ^ PW[45] ^ PW[39] ^ PW[37]), 1);
            PW[54] = rotl((PW[51] ^ PW[46] ^ PW[40] ^ PW[38]), 1);
            PW[55] = rotl((PW[52] ^ PW[47] ^ PW[41] ^ PW[39]), 1);
            PW[56] = rotl((PW[53] ^ PW[48] ^ PW[42] ^ PW[40]), 1);
            PW[57] = rotl((PW[54] ^ PW[49] ^ PW[43] ^ PW[41]), 1);
            PW[58] = rotl((PW[55] ^ PW[50] ^ PW[44] ^ PW[42]), 1);
            PW[59] = rotl((PW[56] ^ PW[51] ^ PW[45] ^ PW[43]), 1);
            PW[60] = rotl((PW[57] ^ PW[52] ^ PW[46] ^ PW[44]), 1);
            PW[61] = rotl((PW[58] ^ PW[53] ^ PW[47] ^ PW[45]), 1);
            PW[62] = rotl((PW[59] ^ PW[54] ^ PW[48] ^ PW[46]), 1);
            PW[63] = rotl((PW[60] ^ PW[55] ^ PW[49] ^ PW[47]), 1);
            PW[64] = rotl((PW[61] ^ PW[56] ^ PW[50] ^ PW[48]), 1);
            PW[65] = rotl((PW[62] ^ PW[57] ^ PW[51] ^ PW[49]), 1);
            PW[66] = rotl((PW[63] ^ PW[58] ^ PW[52] ^ PW[50]), 1);
            PW[67] = rotl((PW[64] ^ PW[59] ^ PW[53] ^ PW[51]), 1);
            PW[68] = rotl((PW[65] ^ PW[60] ^ PW[54] ^ PW[52]), 1);
            PW[69] = rotl((PW[66] ^ PW[61] ^ PW[55] ^ PW[53]), 1);
            PW[70] = rotl((PW[67] ^ PW[62] ^ PW[56] ^ PW[54]), 1);
            PW[71] = rotl((PW[68] ^ PW[63] ^ PW[57] ^ PW[55]), 1);
            PW[72] = rotl((PW[69] ^ PW[64] ^ PW[58] ^ PW[56]), 1);
            PW[73] = rotl((PW[70] ^ PW[65] ^ PW[59] ^ PW[57]), 1);
            PW[74] = rotl((PW[71] ^ PW[66] ^ PW[60] ^ PW[58]), 1);
            PW[75] = rotl((PW[72] ^ PW[67] ^ PW[61] ^ PW[59]), 1);
            PW[76] = rotl((PW[73] ^ PW[68] ^ PW[62] ^ PW[60]), 1);
            PW[77] = rotl((PW[74] ^ PW[69] ^ PW[63] ^ PW[61]), 1);
            PW[78] = rotl((PW[75] ^ PW[70] ^ PW[64] ^ PW[62]), 1);
            PW[79] = rotl((PW[76] ^ PW[71] ^ PW[65] ^ PW[63]), 1);*/
        }

        //------------------------------------------------------------
        //      OPTIMIZED OPERATIONS
        //------------------------------------------------------------
        // Extend the 16 32-bit words into 80 32-bit words w1
        w1_2[16] = PW[16] ^ w1_0_1;
        w1_2[17] = PW[17];
        w1_2[18] = PW[18];
        w1_2[19] = PW[19] ^ w1_0_2;
        w1_2[20] = PW[20];
        w1_2[21] = PW[21];
        w1_2[22] = PW[22] ^ w1_0_3;
        w1_2[23] = PW[23];
        w1_2[24] = PW[24] ^ w1_0_2;
        w1_2[25] = PW[25] ^ w1_0_4;
        w1_2[26] = PW[26];
        w1_2[27] = PW[27];
        w1_2[28] = PW[28] ^ w1_0_5;
        w1_2[29] = PW[29];
        w1_2[30] = PW[30] ^ w1_0_4 ^ w1_0_2;
        w1_2[31] = PW[31] ^ w1_0_6;
        w1_2[32] = PW[32] ^ w1_0_3 ^ w1_0_2;
        w1_2[33] = PW[33];
        w1_2[34] = PW[34] ^ w1_0_7;
        w1_2[35] = PW[35] ^ w1_0_4;
        w1_2[36] = PW[36] ^ w1_0_6___w1_0_4;
        w1_2[37] = PW[37] ^ w1_0_8;
        w1_2[38] = PW[38] ^ w1_0_4;
        w1_2[39] = PW[39];
        w1_2[40] = PW[40] ^ w1_0_4 ^ w1_0_9;
        w1_2[41] = PW[41];
        w1_2[42] = PW[42] ^ w1_0_6 ^ w1_0_8;
        w1_2[43] = PW[43] ^ w1_0_10;
        w1_2[44] = PW[44] ^ w1_0_6 ^ w1_0_3 ^ w1_0_7;
        w1_2[45] = PW[45];
        w1_2[46] = PW[46] ^ w1_0_4 ^ w1_0_11;
        w1_2[47] = PW[47] ^ w1_0_8___w1_0_4;
        w1_2[48] = PW[48] ^ w1_0_8___w1_0_4 ^ w1_0_3 ^ w1_0_10 ^ w1_0_5;
        w1_2[49] = PW[49] ^ w1_0_12;
        w1_2[50] = PW[50] ^ w1_0_8;
        w1_2[51] = PW[51] ^ w1_0_6___w1_0_4;
        w1_2[52] = PW[52] ^ w1_0_8___w1_0_4 ^ w1_0_13;
        w1_2[53] = PW[53];
        w1_2[54] = PW[54] ^ w1_0_7 ^ w1_0_10 ^ w1_0_12;
        w1_2[55] = PW[55] ^ w1_0_14;
        w1_2[56] = PW[56] ^ w1_0_6___w1_0_4___w1_0_7 ^ w1_0_11 ^ w1_0_10;
        w1_2[57] = PW[57] ^ w1_0_8;
        w1_2[58] = PW[58] ^ w1_0_8___w1_0_4 ^ w1_0_15;
        w1_2[59] = PW[59] ^ w1_0_8___w1_0_12;
        w1_2[60] = PW[60] ^ w1_0_8___w1_0_12 ^ w1_0_4 ^ w1_0_7 ^ w1_0_14;
        w1_2[61] = PW[61] ^ w1_0_16;
        w1_2[62] = PW[62] ^ w1_0_6___w1_0_4 ^ w1_0_8___w1_0_12;
        w1_2[63] = PW[63] ^ w1_0_8;
        w1_2[64] = PW[64] ^ w1_0_6___w1_0_4___w1_0_7 ^ w1_0_8___w1_0_12 ^ w1_0_17;
        w1_2[65] = PW[65];
        w1_2[66] = PW[66] ^ w1_0_14 ^ w1_0_16;
        w1_2[67] = PW[67] ^ w1_0_8 ^ w1_0_18;
        w1_2[68] = PW[68] ^ w1_0_11 ^ w1_0_14 ^ w1_0_15;
        w1_2[69] = PW[69];
        w1_2[70] = PW[70] ^ w1_0_12 ^ w1_0_19;
        w1_2[71] = PW[71] ^ w1_0_12 ^ w1_0_16;
        w1_2[72] = PW[72] ^ w1_0_11 ^ w1_0_12 ^ w1_0_18 ^ w1_0_13 ^ w1_0_16 ^ w1_0_5;
        w1_2[73] = PW[73] ^ w1_0_20;
        w1_2[74] = PW[74] ^ w1_0_8 ^ w1_0_16;
        w1_2[75] = PW[75] ^ w1_0_6 ^ w1_0_12 ^ w1_0_14;

        w1_2[76] = PW[76] ^ w1_0_7 ^ w1_0_8___w1_0_12 ^ w1_0_16 ^ w1_0_21;
        w1_2[77] = PW[77];
        w1_2[78] = PW[78] ^ w1_0_7 ^ w1_0_8 ^ w1_0_15 ^ w1_0_18 ^ w1_0_20;
        w1_2[79] = PW[79] ^ w1_0_8 ^ w1_0_22;

        // for(i = 0; i < 80; i++){
        //     printf("w1_2[%d] : %8X\n", i, w1_2[i]);
        // }


        // PW[76] = rotl((w1_2[73] ^ w1_2[68] ^ w1_2[62] ^ w1_2[60]), 1);
        //     ^ w1_0_20;                                      |REMOVE         ^ w1_0_6   |+1 to all|-->   
        //     ^ w1_0_11 ^ w1_0_14 ^ w1_0_15;                      REPEATS|--> ^ w1_0_7
        //     ^ w1_0_6___w1_0_4 ^ w1_0_8___w1_0_12;                           ^ w1_0_11
        //     ^ w1_0_8___w1_0_12 ^ w1_0_4 ^ w1_0_7 ^ w1_0_14;                 ^ w1_0_15
        //                                                                     ^ w1_0_20                                                                  

        // PW[77] = rotl((w1_2[74] ^ w1_2[69] ^ w1_2[63] ^ w1_2[61]), 1);
        //     ^ w1_0_8 ^ w1_0_16;     |REMOVE             
        //     ^ w1_0_8;                   REPEATS|-->
        //     ^ w1_0_16;

        // PW[78] = rotl((w1_2[75] ^ w1_2[70] ^ w1_2[64] ^ w1_2[62]), 1);
        //    ^ w1_0_6 ^ w1_0_12 ^ w1_0_14;                            |REMOVE         ^ w1_0_6    |+1 to all|-->
        //    ^ w1_0_12 ^ w1_0_19;                                         REPEATS|--> ^ w1_0_7
        //    ^ w1_0_6___w1_0_4___w1_0_7 ^ w1_0_8___w1_0_12 ^ w1_0_17;                 ^ w1_0_14
        //    ^ w1_0_6___w1_0_4 ^ w1_0_8___w1_0_12;                                    ^ w1_0_17
        //                                                                             ^ w1_0_19

        // PW[79] = rotl((w1_2[76] ^ w1_2[71] ^ w1_2[65] ^ w1_2[63]), 1);
        //     ^ w1_0_7 ^ w1_0_8 ^ w1_0_12 ^ w1_0_16 ^ w1_0_21; |REMOVE         ^ w1_0_7    |+1 to all|-->
        //     ^ w1_0_12 ^ w1_0_16;                                 REPEATS|--> ^ w1_0_21
        //     ^ w1_0_8;

        // Extend the 16 32-bit words into 80 32-bit words w2
        w2_2[16] = PW[16] ^ w2_0_1;
        w2_2[17] = PW[17];
        w2_2[18] = PW[18];
        w2_2[19] = PW[19] ^ w2_0_2;
        w2_2[20] = PW[20];
        w2_2[21] = PW[21];
        w2_2[22] = PW[22] ^ w2_0_3;
        w2_2[23] = PW[23];
        w2_2[24] = PW[24] ^ w2_0_2;
        w2_2[25] = PW[25] ^ w2_0_4;
        w2_2[26] = PW[26];
        w2_2[27] = PW[27];
        w2_2[28] = PW[28] ^ w2_0_5;
        w2_2[29] = PW[29];
        w2_2[30] = PW[30] ^ w2_0_4 ^ w2_0_2;
        w2_2[31] = PW[31] ^ w2_0_6;
        w2_2[32] = PW[32] ^ w2_0_3 ^ w2_0_2;
        w2_2[33] = PW[33];
        w2_2[34] = PW[34] ^ w2_0_7;
        w2_2[35] = PW[35] ^ w2_0_4;
        w2_2[36] = PW[36] ^ w2_0_6___w2_0_4;
        w2_2[37] = PW[37] ^ w2_0_8;
        w2_2[38] = PW[38] ^ w2_0_4;
        w2_2[39] = PW[39];
        w2_2[40] = PW[40] ^ w2_0_4 ^ w2_0_9;
        w2_2[41] = PW[41];
        w2_2[42] = PW[42] ^ w2_0_6 ^ w2_0_8;
        w2_2[43] = PW[43] ^ w2_0_10;
        w2_2[44] = PW[44] ^ w2_0_6 ^ w2_0_3 ^ w2_0_7;
        w2_2[45] = PW[45];
        w2_2[46] = PW[46] ^ w2_0_4 ^ w2_0_11;
        w2_2[47] = PW[47] ^ w2_0_8___w2_0_4;
        w2_2[48] = PW[48] ^ w2_0_8___w2_0_4 ^ w2_0_3 ^ w2_0_10 ^ w2_0_5;
        w2_2[49] = PW[49] ^ w2_0_12;
        w2_2[50] = PW[50] ^ w2_0_8;
        w2_2[51] = PW[51] ^ w2_0_6___w2_0_4;
        w2_2[52] = PW[52] ^ w2_0_8___w2_0_4 ^ w2_0_13;
        w2_2[53] = PW[53];
        w2_2[54] = PW[54] ^ w2_0_7 ^ w2_0_10 ^ w2_0_12;
        w2_2[55] = PW[55] ^ w2_0_14;
        w2_2[56] = PW[56] ^ w2_0_6___w2_0_4___w2_0_7 ^ w2_0_11 ^ w2_0_10;
        w2_2[57] = PW[57] ^ w2_0_8;
        w2_2[58] = PW[58] ^ w2_0_8___w2_0_4 ^ w2_0_15;
        w2_2[59] = PW[59] ^ w2_0_8___w2_0_12;
        w2_2[60] = PW[60] ^ w2_0_8___w2_0_12 ^ w2_0_4 ^ w2_0_7 ^ w2_0_14;
        w2_2[61] = PW[61] ^ w2_0_16;
        w2_2[62] = PW[62] ^ w2_0_6___w2_0_4 ^ w2_0_8___w2_0_12;
        w2_2[63] = PW[63] ^ w2_0_8;
        w2_2[64] = PW[64] ^ w2_0_6___w2_0_4___w2_0_7 ^ w2_0_8___w2_0_12 ^ w2_0_17;
        w2_2[65] = PW[65];
        w2_2[66] = PW[66] ^ w2_0_14 ^ w2_0_16;
        w2_2[67] = PW[67] ^ w2_0_8 ^ w2_0_18;
        w2_2[68] = PW[68] ^ w2_0_11 ^ w2_0_14 ^ w2_0_15;
        w2_2[69] = PW[69];
        w2_2[70] = PW[70] ^ w2_0_12 ^ w2_0_19;
        w2_2[71] = PW[71] ^ w2_0_12 ^ w2_0_16;
        w2_2[72] = PW[72] ^ w2_0_11 ^ w2_0_12 ^ w2_0_18 ^ w2_0_13 ^ w2_0_16 ^ w2_0_5;
        w2_2[73] = PW[73] ^ w2_0_20;
        w2_2[74] = PW[74] ^ w2_0_8 ^ w2_0_16;
        w2_2[75] = PW[75] ^ w2_0_6 ^ w2_0_12 ^ w2_0_14;

        w2_2[76] = PW[76] ^ w2_0_7 ^ w2_0_8___w2_0_12 ^ w2_0_16 ^ w2_0_21;
        w2_2[77] = PW[77];
        w2_2[78] = PW[78] ^ w2_0_7 ^ w2_0_8 ^ w2_0_15 ^ w2_0_18 ^ w2_0_20;
        w2_2[79] = PW[79] ^ w2_0_8 ^ w2_0_22;   

        
        // Extend the 16 32-bit words into 80 32-bit words w3
        w3_2[16] = PW[16] ^ w3_0_1;
        w3_2[17] = PW[17];
        w3_2[18] = PW[18];
        w3_2[19] = PW[19] ^ w3_0_2;
        w3_2[20] = PW[20];
        w3_2[21] = PW[21];
        w3_2[22] = PW[22] ^ w3_0_3;
        w3_2[23] = PW[23];
        w3_2[24] = PW[24] ^ w3_0_2;
        w3_2[25] = PW[25] ^ w3_0_4;
        w3_2[26] = PW[26];
        w3_2[27] = PW[27];
        w3_2[28] = PW[28] ^ w3_0_5;
        w3_2[29] = PW[29];
        w3_2[30] = PW[30] ^ w3_0_4 ^ w3_0_2;
        w3_2[31] = PW[31] ^ w3_0_6;
        w3_2[32] = PW[32] ^ w3_0_3 ^ w3_0_2;
        w3_2[33] = PW[33];
        w3_2[34] = PW[34] ^ w3_0_7;
        w3_2[35] = PW[35] ^ w3_0_4;
        w3_2[36] = PW[36] ^ w3_0_6___w3_0_4;
        w3_2[37] = PW[37] ^ w3_0_8;
        w3_2[38] = PW[38] ^ w3_0_4;
        w3_2[39] = PW[39];
        w3_2[40] = PW[40] ^ w3_0_4 ^ w3_0_9;
        w3_2[41] = PW[41];
        w3_2[42] = PW[42] ^ w3_0_6 ^ w3_0_8;
        w3_2[43] = PW[43] ^ w3_0_10;
        w3_2[44] = PW[44] ^ w3_0_6 ^ w3_0_3 ^ w3_0_7;
        w3_2[45] = PW[45];
        w3_2[46] = PW[46] ^ w3_0_4 ^ w3_0_11;
        w3_2[47] = PW[47] ^ w3_0_8___w3_0_4;
        w3_2[48] = PW[48] ^ w3_0_8___w3_0_4 ^ w3_0_3 ^ w3_0_10 ^ w3_0_5;
        w3_2[49] = PW[49] ^ w3_0_12;
        w3_2[50] = PW[50] ^ w3_0_8;
        w3_2[51] = PW[51] ^ w3_0_6___w3_0_4;
        w3_2[52] = PW[52] ^ w3_0_8___w3_0_4 ^ w3_0_13;
        w3_2[53] = PW[53];
        w3_2[54] = PW[54] ^ w3_0_7 ^ w3_0_10 ^ w3_0_12;
        w3_2[55] = PW[55] ^ w3_0_14;
        w3_2[56] = PW[56] ^ w3_0_6___w3_0_4___w3_0_7 ^ w3_0_11 ^ w3_0_10;
        w3_2[57] = PW[57] ^ w3_0_8;
        w3_2[58] = PW[58] ^ w3_0_8___w3_0_4 ^ w3_0_15;
        w3_2[59] = PW[59] ^ w3_0_8___w3_0_12;
        w3_2[60] = PW[60] ^ w3_0_8___w3_0_12 ^ w3_0_4 ^ w3_0_7 ^ w3_0_14;
        w3_2[61] = PW[61] ^ w3_0_16;
        w3_2[62] = PW[62] ^ w3_0_6___w3_0_4 ^ w3_0_8___w3_0_12;
        w3_2[63] = PW[63] ^ w3_0_8;
        w3_2[64] = PW[64] ^ w3_0_6___w3_0_4___w3_0_7 ^ w3_0_8___w3_0_12 ^ w3_0_17;
        w3_2[65] = PW[65];
        w3_2[66] = PW[66] ^ w3_0_14 ^ w3_0_16;
        w3_2[67] = PW[67] ^ w3_0_8 ^ w3_0_18;
        w3_2[68] = PW[68] ^ w3_0_11 ^ w3_0_14 ^ w3_0_15;
        w3_2[69] = PW[69];
        w3_2[70] = PW[70] ^ w3_0_12 ^ w3_0_19;
        w3_2[71] = PW[71] ^ w3_0_12 ^ w3_0_16;
        w3_2[72] = PW[72] ^ w3_0_11 ^ w3_0_12 ^ w3_0_18 ^ w3_0_13 ^ w3_0_16 ^ w3_0_5;
        w3_2[73] = PW[73] ^ w3_0_20;
        w3_2[74] = PW[74] ^ w3_0_8 ^ w3_0_16;
        w3_2[75] = PW[75] ^ w3_0_6 ^ w3_0_12 ^ w3_0_14;

        w3_2[76] = PW[76] ^ w3_0_7 ^ w3_0_8___w3_0_12 ^ w3_0_16 ^ w3_0_21;
        w3_2[77] = PW[77];
        w3_2[78] = PW[78] ^ w3_0_7 ^ w3_0_8 ^ w3_0_15 ^ w3_0_18 ^ w3_0_20;
        w3_2[79] = PW[79] ^ w3_0_8 ^ w3_0_22;


        // Extend the 16 32-bit words into 80 32-bit words w4
        w4_2[16] = PW[16] ^ w4_0_1;
        w4_2[17] = PW[17];
        w4_2[18] = PW[18];
        w4_2[19] = PW[19] ^ w4_0_2;
        w4_2[20] = PW[20];
        w4_2[21] = PW[21];
        w4_2[22] = PW[22] ^ w4_0_3;
        w4_2[23] = PW[23];
        w4_2[24] = PW[24] ^ w4_0_2;
        w4_2[25] = PW[25] ^ w4_0_4;
        w4_2[26] = PW[26];
        w4_2[27] = PW[27];
        w4_2[28] = PW[28] ^ w4_0_5;
        w4_2[29] = PW[29];
        w4_2[30] = PW[30] ^ w4_0_4 ^ w4_0_2;
        w4_2[31] = PW[31] ^ w4_0_6;
        w4_2[32] = PW[32] ^ w4_0_3 ^ w4_0_2;
        w4_2[33] = PW[33];
        w4_2[34] = PW[34] ^ w4_0_7;
        w4_2[35] = PW[35] ^ w4_0_4;
        w4_2[36] = PW[36] ^ w4_0_6___w4_0_4;
        w4_2[37] = PW[37] ^ w4_0_8;
        w4_2[38] = PW[38] ^ w4_0_4;
        w4_2[39] = PW[39];
        w4_2[40] = PW[40] ^ w4_0_4 ^ w4_0_9;
        w4_2[41] = PW[41];
        w4_2[42] = PW[42] ^ w4_0_6 ^ w4_0_8;
        w4_2[43] = PW[43] ^ w4_0_10;
        w4_2[44] = PW[44] ^ w4_0_6 ^ w4_0_3 ^ w4_0_7;
        w4_2[45] = PW[45];
        w4_2[46] = PW[46] ^ w4_0_4 ^ w4_0_11;
        w4_2[47] = PW[47] ^ w4_0_8___w4_0_4;
        w4_2[48] = PW[48] ^ w4_0_8___w4_0_4 ^ w4_0_3 ^ w4_0_10 ^ w4_0_5;
        w4_2[49] = PW[49] ^ w4_0_12;
        w4_2[50] = PW[50] ^ w4_0_8;
        w4_2[51] = PW[51] ^ w4_0_6___w4_0_4;
        w4_2[52] = PW[52] ^ w4_0_8___w4_0_4 ^ w4_0_13;
        w4_2[53] = PW[53];
        w4_2[54] = PW[54] ^ w4_0_7 ^ w4_0_10 ^ w4_0_12;
        w4_2[55] = PW[55] ^ w4_0_14;
        w4_2[56] = PW[56] ^ w4_0_6___w4_0_4___w4_0_7 ^ w4_0_11 ^ w4_0_10;
        w4_2[57] = PW[57] ^ w4_0_8;
        w4_2[58] = PW[58] ^ w4_0_8___w4_0_4 ^ w4_0_15;
        w4_2[59] = PW[59] ^ w4_0_8___w4_0_12;
        w4_2[60] = PW[60] ^ w4_0_8___w4_0_12 ^ w4_0_4 ^ w4_0_7 ^ w4_0_14;
        w4_2[61] = PW[61] ^ w4_0_16;
        w4_2[62] = PW[62] ^ w4_0_6___w4_0_4 ^ w4_0_8___w4_0_12;
        w4_2[63] = PW[63] ^ w4_0_8;
        w4_2[64] = PW[64] ^ w4_0_6___w4_0_4___w4_0_7 ^ w4_0_8___w4_0_12 ^ w4_0_17;
        w4_2[65] = PW[65];
        w4_2[66] = PW[66] ^ w4_0_14 ^ w4_0_16;
        w4_2[67] = PW[67] ^ w4_0_8 ^ w4_0_18;
        w4_2[68] = PW[68] ^ w4_0_11 ^ w4_0_14 ^ w4_0_15;
        w4_2[69] = PW[69];
        w4_2[70] = PW[70] ^ w4_0_12 ^ w4_0_19;
        w4_2[71] = PW[71] ^ w4_0_12 ^ w4_0_16;
        w4_2[72] = PW[72] ^ w4_0_11 ^ w4_0_12 ^ w4_0_18 ^ w4_0_13 ^ w4_0_16 ^ w4_0_5;
        w4_2[73] = PW[73] ^ w4_0_20;
        w4_2[74] = PW[74] ^ w4_0_8 ^ w4_0_16;
        w4_2[75] = PW[75] ^ w4_0_6 ^ w4_0_12 ^ w4_0_14;

        w4_2[76] = PW[76] ^ w4_0_7 ^ w4_0_8___w4_0_12 ^ w4_0_16 ^ w4_0_21;
        w4_2[77] = PW[77];
        w4_2[78] = PW[78] ^ w4_0_7 ^ w4_0_8 ^ w4_0_15 ^ w4_0_18 ^ w4_0_20;
        w4_2[79] = PW[79] ^ w4_0_8 ^ w4_0_22;

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
        __m128i vecTemp = temp(vecA, vecE, vecF, k, w1_2[0], w2_2[0], w3_2[0], w4_2[0]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[1], w2_2[1], w3_2[1], w4_2[1]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[2], w2_2[2], w3_2[2], w4_2[2]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[3], w2_2[3], w3_2[3], w4_2[3]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[4], w2_2[4], w3_2[4], w4_2[4]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[5], w2_2[5], w3_2[5], w4_2[5]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[6], w2_2[6], w3_2[6], w4_2[6]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[7], w2_2[7], w3_2[7], w4_2[7]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[8], w2_2[8], w3_2[8], w4_2[8]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[9], w2_2[9], w3_2[9], w4_2[9]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[10], w2_2[10], w3_2[10], w4_2[10]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[11], w2_2[11], w3_2[11], w4_2[11]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[12], w2_2[12], w3_2[12], w4_2[12]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[13], w2_2[13], w3_2[13], w4_2[13]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[14], w2_2[14], w3_2[14], w4_2[14]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[15], w2_2[15], w3_2[15], w4_2[15]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[16], w2_2[16], w3_2[16], w4_2[16]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[17], w2_2[17], w3_2[17], w4_2[17]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[18], w2_2[18], w3_2[18], w4_2[18]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f1(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[19], w2_2[19], w3_2[19], w4_2[19]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        // -----------------------------------------

        k = 0x6ED9EBA1;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[20], w2_2[20], w3_2[20], w4_2[20]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[21], w2_2[21], w3_2[21], w4_2[21]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[22], w2_2[22], w3_2[22], w4_2[22]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[23], w2_2[23], w3_2[23], w4_2[23]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[24], w2_2[24], w3_2[24], w4_2[24]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[25], w2_2[25], w3_2[25], w4_2[25]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[26], w2_2[26], w3_2[26], w4_2[26]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[27], w2_2[27], w3_2[27], w4_2[27]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[28], w2_2[28], w3_2[28], w4_2[28]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[29], w2_2[29], w3_2[29], w4_2[29]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[30], w2_2[30], w3_2[30], w4_2[30]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[31], w2_2[31], w3_2[31], w4_2[31]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[32], w2_2[32], w3_2[32], w4_2[32]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[33], w2_2[33], w3_2[33], w4_2[33]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[34], w2_2[34], w3_2[34], w4_2[34]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[35], w2_2[35], w3_2[35], w4_2[35]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[36], w2_2[36], w3_2[36], w4_2[36]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[37], w2_2[37], w3_2[37], w4_2[37]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[38], w2_2[38], w3_2[38], w4_2[38]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f2(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[39], w2_2[39], w3_2[39], w4_2[39]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        // -----------------------

        k = 0x8F1BBCDC;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[40], w2_2[40], w3_2[40], w4_2[40]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[41], w2_2[41], w3_2[41], w4_2[41]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[42], w2_2[42], w3_2[42], w4_2[42]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[43], w2_2[43], w3_2[43], w4_2[43]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[44], w2_2[44], w3_2[44], w4_2[44]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[45], w2_2[45], w3_2[45], w4_2[45]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[46], w2_2[46], w3_2[46], w4_2[46]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[47], w2_2[47], w3_2[47], w4_2[47]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[48], w2_2[48], w3_2[48], w4_2[48]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[49], w2_2[49], w3_2[49], w4_2[49]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[50], w2_2[50], w3_2[50], w4_2[50]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[51], w2_2[51], w3_2[51], w4_2[51]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[52], w2_2[52], w3_2[52], w4_2[52]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[53], w2_2[53], w3_2[53], w4_2[53]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[54], w2_2[54], w3_2[54], w4_2[54]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[55], w2_2[55], w3_2[55], w4_2[55]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[56], w2_2[56], w3_2[56], w4_2[56]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[57], w2_2[57], w3_2[57], w4_2[57]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[58], w2_2[58], w3_2[58], w4_2[58]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f3(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[59], w2_2[59], w3_2[59], w4_2[59]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        // ------------------------------------

        k = 0xCA62C1D6;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[60], w2_2[60], w3_2[60], w4_2[60]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[61], w2_2[61], w3_2[61], w4_2[61]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[62], w2_2[62], w3_2[62], w4_2[62]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[63], w2_2[63], w3_2[63], w4_2[63]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[64], w2_2[64], w3_2[64], w4_2[64]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[65], w2_2[65], w3_2[65], w4_2[65]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[66], w2_2[66], w3_2[66], w4_2[66]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[67], w2_2[67], w3_2[67], w4_2[67]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[68], w2_2[68], w3_2[68], w4_2[68]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[69], w2_2[69], w3_2[69], w4_2[69]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[70], w2_2[70], w3_2[70], w4_2[70]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[71], w2_2[71], w3_2[71], w4_2[71]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[72], w2_2[72], w3_2[72], w4_2[72]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[73], w2_2[73], w3_2[73], w4_2[73]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[74], w2_2[74], w3_2[74], w4_2[74]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[75], w2_2[75], w3_2[75], w4_2[75]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[76], w2_2[76], w3_2[76], w4_2[76]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[77], w2_2[77], w3_2[77], w4_2[77]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[78], w2_2[78], w3_2[78], w4_2[78]);
        vecE = vecD;
        vecD = vecC;
        vecC = setC(vecB);
        vecB = vecA;
        vecA = vecTemp;

        vecF = f4(vecB,vecC,vecD);
        vecTemp = temp(vecA, vecE, vecF, k, w1_2[79], w2_2[79], w3_2[79], w4_2[79]);
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
}

void printSHA(uint32_t hash_buffer[5])
{
    printf("SHA-1: %x%x%x%x%x\n", hash_buffer[0], hash_buffer[1], hash_buffer[2], hash_buffer[3], hash_buffer[4]);
    //printf("SHA-1: %X%X%X%X%X\n", hash_buffer[4], hash_buffer[3], hash_buffer[2], hash_buffer[1], hash_buffer[0]);
}

bool SHAcompare(uint32_t hash_buffer[5], uint32_t input_hash[5])
{
    return !memcmp(hash_buffer, input_hash, 20);
}
