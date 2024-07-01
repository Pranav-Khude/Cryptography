/*
Name: Khude Pranav Eknath
Student ID: 202151077
Assignment 3
CS364: Introduction to Cryptography and Network Security LAB
*/

#include<stdio.h>
#include <stdlib.h>
#include <time.h>

// globally defining the mixCoulmnMatrix given in the question
unsigned char mixCoulmnMatrix[4][4]={{1,4,4,5},{5,1,4,4},{4,5,1,4},{4,4,5,1}};
// globally defining the inverseMixCoulmnMatrix given in the question
unsigned char inverseMixCoulmnMatrix[4][4]={{165,7,26,115},{115,165,7,26},{26,115,165,7},{7,26,115,165}};
// globally defining the subbyteMatrix
unsigned char subbyteMatrix[16][16]={0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
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

// globally defining the inversesubbyteMatrix to store the inverse of subbyte operation
unsigned char invSubbyteMatrix[256];

unsigned char rCon[10]={0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

unsigned int roundKeys[44];

// Function to perform rotWord in the key expansion
unsigned int rotWord(unsigned int word){
    return (word<<8)|(word>>24);
}
// Function to perform subWord in the key expansion
unsigned int subWord(unsigned int word){
    unsigned int temp=0;
    for(int i=0;i<4;i++){
        unsigned char temp1=word>>(24-8*i);
        unsigned char row=temp1>>4;
        unsigned char col=temp1&0x0f;
        temp=temp|(subbyteMatrix[row][col]<<(24-8*i));
    }
    return temp;
}

// Key exapansion function to generate the round keys
void keyExpansion(unsigned int key[4],unsigned int roundKeys[44]){
    for(int i=0;i<4;i++){
        roundKeys[i]=key[i];
    }
    for(int i=4;i<44;i++){
        unsigned int temp=roundKeys[i-1];
        if(i%4==0){
            temp=subWord(rotWord(temp))^((unsigned int)rCon[i/4-1]<<24);
        }
        roundKeys[i]=roundKeys[i-4]^temp;
    }
}
// converting the plaintext array of size 16 to a 4x4 matrix
void convertPlainTextToMatrix(unsigned char plainText[16],unsigned char plainTextMatrix[4][4]){
    for(int i=0;i<4;i++){
        for(int j=0;j<4;j++){
            // here 1st four elements of the plainText array are stored in the first column of the matrix
            // here 2nd four elements of the plainText array are stored in the second column of the matrix
            // here 3rd four elements of the plainText array are stored in the third column of the matrix
            // here 4th four elements of the plainText array are stored in the fourth column of the matrix
            plainTextMatrix[j][i]=plainText[4*i+j];
        }
    }
}
// helping function for multiply function
unsigned char subMultiply(unsigned char num,int i){
    while(i!=0){
        if(num>>7==1){
        num=(num<<1)^(27);
        }else{
        num=num<<1;
        }
        i--;
    }
    return num;
}
// function to multiply two numbers in the field
unsigned char multiply(unsigned char num1,unsigned char num2){
    unsigned char ans=0;
    for(int i=0;i<8;i++){
        if(num2&1){
            ans=ans^subMultiply(num1,i);
        }
        num2=num2>>1;
    }
    return ans;
}

// function to generate the inversesubbyteMatrix
void createInvSubbyteMatrix(){
    for(int i=0;i<256;i++){
        unsigned char temp=multiply(201,i)^39;
        unsigned char row=temp>>4;
        unsigned char col=temp&0x0f;
        invSubbyteMatrix[subbyteMatrix[row][col]]=i;
    }
}
// function to perform the subbyte operation in the encryption(performs subbyte operation on each element of the matrix)
void encryptionSubbyte(unsigned char subbyteinput[4][4],unsigned char shiftrowinput[4][4]){
    for(int i=0;i<4;i++){
        for(int j=0;j<4;j++){
            unsigned char temp=multiply(201,subbyteinput[i][j])^39; //multiplying with 201 and xoring with 39
            unsigned char row=temp>>4;
            unsigned char col=temp&0x0f;
            shiftrowinput[i][j]=subbyteMatrix[row][col];
        }
    }
}
// function to perform the shiftrow operation in the encryption
void encryptionShiftRow(unsigned char shiftrowinput[4][4],unsigned char mixcolumninput[4][4]){
    for(int i=0;i<4;i++){
        unsigned char temp[4]={shiftrowinput[i][0],shiftrowinput[i][1],shiftrowinput[i][2],shiftrowinput[i][3]};
        for(int j=0;j<4;j++){
            mixcolumninput[i][j]=temp[(j+i)%4];
        }
    }
}
// function to perform the mixcolumn operation in the encryption
void encryptionMixColumn(unsigned char mixcolumninput[4][4],unsigned char cipherText[4][4],unsigned char round){
    for(int i=0;i<4;i++){
        for(int j=0;j<4;j++){
            unsigned char temp=0;
            // below condition ensures that the last round does not perform the mixcolumn operation
            if(round!=9){
                for(int k=0;k<4;k++){
                    temp=temp^multiply(mixCoulmnMatrix[i][k],mixcolumninput[k][j]);
                }
            }else{
                // instead of performing the mixcolumn operation in the last round we just copy the value
                temp=mixcolumninput[i][j];
            }
            cipherText[i][j]=temp;
        }
    }
}
// function to perform decryption of the subbyte operation with help of inversesubbyteMatrix
void decrypttionSubbyte(unsigned char decryptedSubbyteinput[4][4],unsigned char decryptedText[4][4]){
    for(int i=0;i<4;i++){
        for(int j=0;j<4;j++){
            unsigned char temp=invSubbyteMatrix[decryptedSubbyteinput[i][j]];
            decryptedText[i][j]=temp;
        }
    }
}
// function to perform the shiftrow operation in the decryption
void decryptionShiftRow(unsigned char decryptedShiftRowinput[4][4],unsigned char decryptedSubbyteinput[4][4]){
    for(int i=0;i<4;i++){
        unsigned char temp[4]={decryptedShiftRowinput[i][0],decryptedShiftRowinput[i][1],decryptedShiftRowinput[i][2],decryptedShiftRowinput[i][3]};
        for(int j=0;j<4;j++){
            decryptedSubbyteinput[i][j]=temp[(j-i+4)%4];
        }
    }
}
// function to perform the mixcolumn operation in the decryption
void decryptionMixColumn(unsigned char cipherText[4][4],unsigned char decryptedShiftRowinput[4][4],unsigned char round){
    for(int i=0;i<4;i++){
        for(int j=0;j<4;j++){
            unsigned char temp=0;
            // below condition ensures that the first round of decryption does not perform 
            // the mixcolumn operation as the last round of encryption does not perform the mixcolumn operation
            if(round!=0){
                for(int k=0;k<4;k++){
                    temp=temp^multiply(inverseMixCoulmnMatrix[i][k],cipherText[k][j]);
                }
            }else{
                temp=cipherText[i][j];
            }
            decryptedShiftRowinput[i][j]=temp;
        }
    }
}
// function to perform the encryption of the plaintext
// functions that calls all the above functions of encryption to perform the encryption
void encryption(unsigned char PlainText[16],unsigned char CipherText[16],unsigned int key[4]){
    keyExpansion(key,roundKeys);
    unsigned char XORedPlainText[16];
    // initial XOR operation with the first round key
    for(int i=0;i<4;i++){
        for(int j=0;j<4;j++){
            XORedPlainText[4*i+j]=PlainText[4*i+j]^((roundKeys[i]>>(24-8*j))&0xff);
        }
    }
    unsigned char subbyteinput[4][4];
    unsigned char shiftrowinput[4][4];
    unsigned char mixcolumninput[4][4];
    unsigned char cipherTextMatrix[4][4];
    for(int i=0;i<10;i++){
        convertPlainTextToMatrix(XORedPlainText,subbyteinput);
        encryptionSubbyte(subbyteinput,shiftrowinput);
        encryptionShiftRow(shiftrowinput,mixcolumninput);
        // in function encryptionMixColumn we are passing the round number as the 
        // last round does not perform the mixcolumn operation
        encryptionMixColumn(mixcolumninput,cipherTextMatrix,i);
        for(int i=0;i<4;i++){
            for(int j=0;j<4;j++){
                // converting the matrix back to 16 size array
                CipherText[4*i+j]=cipherTextMatrix[j][i];
            }
        }

        // xoring the round key with the cipher text
        for(int j=0;j<4;j++){
            for(int k=0;k<4;k++){
                XORedPlainText[4*j+k]=CipherText[4*j+k]^((roundKeys[4*(i+1)+j]>>(24-8*k))&0xff);
            }
        }
    }
    // copying the final cipher text to the output
    for(int i=0;i<16;i++){
        CipherText[i]=XORedPlainText[i];
    }
}
// function to perform the decryption of the plaintext
// functions that calls all the above functions of decryption to perform the decryption
void decryption(unsigned char CipherText[16],unsigned char DecryptedText[16],unsigned int key[4]){
    keyExpansion(key,roundKeys);
    unsigned char cipherTextMatrix[4][4];
    unsigned char XORedCipherText[16];
    unsigned char decryptedShiftRowinput[4][4];
    unsigned char decryptedSubbyteinput[4][4];
    unsigned char decryptedText[4][4];
    unsigned char decryptedCipherText[16];
    for(int j=0;j<4;j++){
        for(int k=0;k<4;k++){
            XORedCipherText[4*j+k]=CipherText[4*j+k]^((roundKeys[40+j]>>(24-8*k))&0xff);
        }
    }
    for(int j=0;j<4;j++){
        for(int k=0;k<4;k++){
            CipherText[4*j+k]=XORedCipherText[4*j+k];
        }
    }
    for(int i=0;i<4;i++){
        for(int j=0;j<4;j++){
            cipherTextMatrix[j][i]=CipherText[4*i+j];
        }
    }
    for(int i=0;i<10;i++){
        // in the function decryptionMixColumn we are passing the round number as the
        // first round of decryption does not perform the mixcolumn operation
        decryptionMixColumn(cipherTextMatrix,decryptedShiftRowinput,i);
        decryptionShiftRow(decryptedShiftRowinput,decryptedSubbyteinput);
        decrypttionSubbyte(decryptedSubbyteinput,decryptedText);
        for(int i=0;i<4;i++){
            for(int j=0;j<4;j++){
                decryptedCipherText[4*i+j]=decryptedText[j][i];
            }
        }
        for(int j=0;j<4;j++){
            for(int k=0;k<4;k++){
                CipherText[4*j+k]=decryptedCipherText[4*j+k]^((roundKeys[36-4*i+j]>>(24-8*k))&0xff);
            }
        }
        for(int i=0;i<16;i++){
            cipherTextMatrix[i%4][i/4]=CipherText[i];
        }
    }
    for(int i=0;i<16;i++){
        DecryptedText[i]=CipherText[i];
    }
}
// function to convert the key from 16 char  to 4 integer
void convert(unsigned char k[16],unsigned int key[4]){
    for(int i=0;i<4;i++){
        key[i]=0;
        for(int j=0;j<4;j++){
            key[i]=key[i]|(k[4*i+j]<<(24-8*j));
        }
    }
}
int main(){
    
// calling the function to generate the inversesubbyteMatrix
// createInvSubbyteMatrix();
// unsigned char m1[16];
// unsigned char m2[16];
// // Question 1 and 2:
// // implementing compression function (aes encryption) and 
// // question 2 takes the input from the user and prints the result of the compression function
// printf("Question 1 and 2:\n");
// // Taking the input from the user(m1)
// printf("Enter the plain text m1 in the form of 16 hexadecimal:\n");
// for(int i=0;i<16;i++){
//     scanf("%hhx",&m1[i]);
// }
// // Taking the input from the user(m2)
// printf("Enter the plain text m2 in the form of 16 hexadecimal:\n");
// for(int i=0;i<16;i++){
//     scanf("%hhx",&m2[i]);
// }
// // converting the char m2 of 16 size to integer key of 4 size
// unsigned int key[4];
// convert(m2,key);
// unsigned char compressedText[16];
// // calling the encryption function which acts as the compression function
// encryption(m1,compressedText,key);
// printf("\n");
// // printing the result of the compression function
// printf("Result of compression function h(m1||m2) on m1 and m2:\n");
// for(int i=0;i<16;i++){
//     printf("%x ",compressedText[i]);
// }

// printf("\n \n");
// printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
// printf("\n \n");

// // Question 3 and 4:
// printf("Question 3 and 4:\n");
// unsigned char m1q2[16];
// unsigned char m2q2[16];
// unsigned int keyq2[4];
// // Taking the input from the user(m1) for question 2
// printf("Enter the plain text m1 for Question2 in the form of 16 hexadecimal:\n");
// for(int i=0;i<16;i++){
//     scanf("%hhx",&m1q2[i]);
// }
// // Taking the input from the user(m2) for question 2
// printf("Enter the plain text m2 for Question2 in the form of 16 hexadecimal:\n");
// for(int i=0;i<16;i++){
//     scanf("%hhx",&m2q2[i]);
// }
// // converting the char m2 of 16 size to integer keyq2 of 4 size
// convert(m2q2,keyq2);
// unsigned char compressedTextm1andm2q2[16];
// // calling the encryption function which acts as the compression function
// encryption(m1q2,compressedTextm1andm2q2,keyq2);
// // printing the result of the compression function
// printf("Result of compression function h(m1||m2) on m1 and m2:\n");

// for(int i=0;i<16;i++){
//     printf("%x ",compressedTextm1andm2q2[i]);
// }
// printf("\n");
// // to find the second preimage of m1 and m2
// // in order to find the second pre-image of m1 and m2 we fist randomly generate m2' (which acts as key) then
// // we decrypt the compressed text(h(m1||m2)) by using m2' as key to get m1'
// // the the decrypted text is the m1'
// // then we encrypt m1' and m2' to get the compressed text h(m1'||m2')
// // here h(m1||m2) = h(m1'||m2') therefore m1' and m2' are the second preimage of m1 and m2
// unsigned char m1primeq2[16];
// unsigned char m2primeq2[16];

// // generating m2' randomly which acts as key for the decryption
// srand(time(NULL));
// for(int i = 0;i < 16; i++){
//     m2primeq2[i] = rand() % 256; 
// }
// unsigned int keyprimeq2[4];
// convert(m2primeq2,keyprimeq2);
// // the result of decryption by using m2' as key gets m1'
// decryption(compressedTextm1andm2q2,m1primeq2,keyprimeq2);

// printf("\n");
// // printing m1' and m2'
// printf("m1': ");
// for(int i=0;i<16;i++){
//     printf("%x ",m1primeq2[i]);
// }
// printf("\n");
// printf("m2': ");
// for(int i=0;i<16;i++){
//     printf("%x ",m2primeq2[i]);
// }
// printf("\n");
// unsigned char compressedTextm1primeandm2primeq2[16];
// // calling the encryption function which acts as the compression function
// encryption(m1primeq2,compressedTextm1primeandm2primeq2,keyprimeq2);
// printf("\n");
// printf("Result of compression function h(m1'||m2') on m1' and m2':\n");
// for(int i=0;i<16;i++){
//     printf("%x ",compressedTextm1primeandm2primeq2[i]);
// }
// printf("\n");
// printf("We can see that h(m1||m2) = h(m1'||m2') therefore m1' and m2' are second preimage of m1 and m2.\n");


unsigned char m1[16]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
unsigned int key[4];
convert(m1,key);

keyExpansion(key,roundKeys);

for(int i=0;i<44;i++){
    if(i%4==0){
        printf("\n");
    }
    printf("%x ",roundKeys[i]);
}



return 0;

}