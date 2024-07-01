/*
Name: Khude Pranav Eknath
Student ID: 202151077
Assignment 2
CS364
Question: Write a single C code to implement a 16 round Feistel based block cipher 
          (both encryption and decryption) with the following details.
*/


#include<stdio.h>

// Globally defining the S-box so that it can be used in the entire program without passing it as an argument
unsigned char S1[]={0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
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
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

// Globally defining the round keys so that it can be used in the entire program without 
// passing it as an argument
unsigned int roundKeys[16];

// Function to perform circular left shift
unsigned int circularLeftShift(unsigned int value, int shift) {
    return (value << shift) | (value >> (sizeof(value) * 8 - shift));
}

// Function to find the index of the character in the S-box
unsigned char ind(unsigned char x){
    for(unsigned i=0;i<256;i++){
        if(S1[i]==x){
            return i; //returns the index of the character in the S-box
        }
    }
    return 0; 
}

// Function to perform the sub-encryption(encryption of a single round) of the Feistel cipher
unsigned long long int subencfiestal(unsigned long long int Plaintext, unsigned int Key) {
    unsigned long long int T=0;
    // Breaking the 64-bit plaintext into two 32-bit parts namely L0 and R0
    unsigned int L0 = (Plaintext >> 32);
    unsigned int R0 = Plaintext;
    unsigned int temp=0,L1=0,R1=0;
    unsigned char X0=0, X1=0, X2=0, X3=0;

    // performs the round function
    X3=R0^Key;
    X2=(R0^Key)>>8;
    X1=(R0^Key)>>16;
    X0=(R0^Key)>>24;
    
    // printf("X0: %u X1: %u X2: %u X3:%u    \n",X0,X1,X2,X3);

    X3 = ind(X3);
    X2 = ind(X2);
    X1 = ind(X1);
    X0 = ind(X0);

    // printf("X0: %u X1: %u X2: %u X3:%u    \n",X0,X1,X2,X3);

    temp = (temp|X0);
    temp = (temp<<8)|X1;
    temp = (temp<<8)|X2;
    temp = (temp<<8)|X3;

    L1=R0;

    R1 = L0 ^ temp;
    T=L1;
    
    T=(T<<32)|R1;

    return T; //returns the 64-bit ciphertext for that round
}

// Function to perform the encryption and generating the round keys of the Feistel cipher
unsigned long long int encfiestal(unsigned long long int P, unsigned int K) {
    unsigned int K1=0;
    unsigned char Y0, Y1, Y2, Y3;
    unsigned int temp0=0,temp1=0,temp2=0,temp3=0;
    // loop to generate the round keys and perform the encryption
    for(int i=1;i<=16;i++){
        Y3=K;
        Y2=K>>8;
        Y1=K>>16;
        Y0=K>>24;

        Y0=S1[Y0];
        Y1=S1[Y1];
        Y2=S1[Y2];
        Y3=S1[Y3];

        temp0=(unsigned int)Y0<<24;
        temp1=(unsigned int)Y1<<16;
        temp2=(unsigned int)Y2<<8;
        temp3=Y3;
        K1=temp0|temp1|temp2|temp3;
        // circular left shift on K1
        K=circularLeftShift(K1,i);
        // Storing the round keys in the array roundKeys so that it can be used in the decryption
        roundKeys[i-1]=K;
        // calling the sub-encryption function to perform the encryption of a single round
        P=subencfiestal(P,K);
    }
    printf("The encrypted value is: %llu\n",P);     
    return P;
}
// function to perform the decryption of the Feistel cipher
unsigned long long int decfiestal(unsigned long long int C) {
    // loop for decryption of the Feistel cipher
    for(int i=15;i>=0;i--){
        unsigned int L1 = (C >> 32),R0=0,L0=0;
        unsigned int R1 = C;
        unsigned int temp=0;
        unsigned char X0, X1, X2, X3;

        // round function for decryption
        X3=L1^roundKeys[i];
        X2=(L1^roundKeys[i])>>8;
        X1=(L1^roundKeys[i])>>16;
        X0=(L1^roundKeys[i])>>24;

        X3=ind(X3);
        X2=ind(X2);
        X1=ind(X1);
        X0=ind(X0);

        temp = (temp|X0);
        temp = (temp<<8)|X1;
        temp = (temp<<8)|X2;
        temp = (temp<<8)|X3;
        R0=L1;
        L0 = R1^temp;

        C= ((unsigned long long int)L0 << 32) | R0;
    }
    // printinf decrypted value
   printf("The decrypted value is: %llu\n",C);
   return C;
}
int main(){
    unsigned long long int P,C;
    unsigned int K;

    // Taking Decimal input from the user
    printf("Enter an integer: ");
    scanf("%llu", &P);

    // Taking key as a input from the user
    printf("Enter a key: ");
    scanf("%u", &K);

    C=encfiestal(P,K);
    C=decfiestal(C);

    
    printf("\n"); 
    for(int i=0;i<16;i++){
        printf("The round key %d is: %u\n",i+1,roundKeys[i]);
    }

    return 0;
}