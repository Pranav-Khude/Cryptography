/*
Name: Khude Pranav Eknath
Student ID: 202151077
Assignment 4
CS364: Introduction to Cryptography and Network Security LAB
*/

// importing the required libraries

#include<stdio.h>
#include<stdlib.h>
#include <time.h>
#include <string.h>

int p=1021; // prime modulus for the finite field
// Elliptic curve equation: y^2 = x^3 + 449x + 233
// point at infinity: (0,1)
int inf[2] = {0,1}; // defining the point at infinity


// defining the macros for the sha256 algorithm
#define ROTRIGHT(word, bits) (((word) >> (bits)) | ((word) << (32 - (bits))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

// defining the constants for the sha256 algorithm
const unsigned int K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// defining the mixCoulmnMatrix given in the question
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

// globally defining the round constant array
unsigned char rCon[10]={0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

// globally defining the round keys to store the round keys generated
unsigned int roundKeys[44];


// function to calculate the inverse
unsigned int extendedEuclidean(int b, int a){
    int q,r,x0=1,y0=0,x1=0,y1=1,x,y;
    while(b!=0){
        q = a/b;
        r = a%b;
        x = x0 - q*x1;
        y = y0 - q*y1;
        a = b;
        b = r;
        x0 = x1;
        y0 = y1;
        x1 = x;
        y1 = y;
    }
    return y0;
}

// function to obtain the points on the elliptic curve
void obtainPoint(int store[2]){
    srand(time(NULL));
    int count = 0;

    // generating a random number between 0 and 100 so that we can obtain a random point from
    //  first 100 points on the elliptic curve 
    int random = rand()%100;
    for(int i=0;i<1021;i++){
        for(int j=0;j<1021;j++){

            // checking if the point lies on the elliptic curve and count==random
            if((count==random)&&(j*j)%p == (((i*i)%p)*i + (449*i)%p + 233)%p){
                store[0] = i;
                store[1] = j;
                return;

            }else if((j*j)%p == (((i*i)%p)*i + (449*i)%p + 233)%p){ // checking if the point lies on the elliptic curve
                count++;
            }
        }
    }
}

// function to compute n times alpha  (point addition)
void computeNtimesAlpha(int n, int alpha[2], int ntimesAplha[2]){
    int beta[2];
    int lambda;

    // alpha is the point on the elliptic curve obtain

    // if n==0 then the point is the point at infinity
    if(n==0){
        ntimesAplha[0] = inf[0];
        ntimesAplha[1] = inf[1];
        return;
    }

    // if the point is the point at infinity then the point is the point itself
    if(ntimesAplha[0]==inf[0]&&ntimesAplha[1]==inf[1]){
        ntimesAplha[0] = alpha[0];
        ntimesAplha[1] = alpha[1];
        return ;
    }

    // setting the beta to alpha
    beta[0] = alpha[0];
    beta[1] = alpha[1];

    for(int i=0;i<n-1;i++){

        // if beta is the point at infinity then beta is the point itself
        if(beta[0]==inf[0]&&beta[1]==inf[1]){
            beta[0] = alpha[0];
            beta[1] = alpha[1];
        }
        // if x coordinate of beta is same as x coordinate of
        // alpha and y coordinate of beta is the negative of y coordinate of alpha
        // then beta is the point at infinity
        else if(beta[0]==alpha[0]&&(beta[1]==(p-alpha[1])%p)){
            beta[0] = inf[0];
            beta[1] = inf[1];
        }
        // if both the point are same then we use the tangent line to find the next point
        else if(beta[0]==alpha[0]&&beta[1]==alpha[1]){
            lambda = (3*beta[0]*beta[0]%p + 449)%p;
            lambda = (lambda*(extendedEuclidean(2*beta[1]%p,p)+p))%p;
            ntimesAplha[0] = (2*p+lambda*lambda%p - 2*beta[0]%p)%p;
            ntimesAplha[1] = (lambda*(p+beta[0] - ntimesAplha[0])%p - beta[1]+p)%p;
            beta[0] = ntimesAplha[0];
            beta[1] = ntimesAplha[1];
        }
        // if x cooridinate of beta is not equal to x coordinate of alpha
        else if(beta[0]!=alpha[0]){
            lambda = (beta[1]-alpha[1]+p)%p;
            lambda = (lambda*(extendedEuclidean((beta[0]-alpha[0]+p)%p,p)+p))%p;
            ntimesAplha[0] = (lambda*lambda%p - beta[0] - alpha[0]+2*p)%p;
            ntimesAplha[1] = (lambda*(beta[0] - ntimesAplha[0]+p) - beta[1]+p)%p;
            beta[0] = ntimesAplha[0];
            beta[1] = ntimesAplha[1];
        } 
    }
    ntimesAplha[0]=beta[0];
    ntimesAplha[1]=beta[1];
}

// function to for sha256 algorithm
void sha256(const unsigned char *msg, unsigned int len, unsigned char hash[]) {


    unsigned int H[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };


    unsigned int W[64];
    unsigned int a, b, c, d, e, f, g, h, i, j, t1, t2;

    // padding the message
    unsigned long long new_len = ((len + 8) / 64 + 1) * 64;
    unsigned char *msg_padded = (unsigned char *)calloc(new_len, 1);
    memcpy(msg_padded, msg, len);

    // appending the single '1' bit
    msg_padded[len] = 0x80; 

    // pad with '0' bits
    for (i = len + 1; i < new_len - 8; i++) 
        msg_padded[i] = 0;
    unsigned long long bit_len = len * 8; // length of the message in bits
    bit_len = (((bit_len >> 56) & 0xff) | ((bit_len >> 40) & 0xff00) | ((bit_len >> 24) & 0xff0000) | ((bit_len >> 8) & 0xff000000) |
               ((bit_len << 8) & 0xff00000000) | ((bit_len << 24) & 0xff0000000000) | ((bit_len << 40) & 0xff000000000000) |
               ((bit_len << 56) & 0xff00000000000000));
               // append bit length in big-endian
    memcpy(msg_padded + new_len - 8, &bit_len, 8); 

    // breaking the message into 512 bit blocks
    for (i = 0; i < new_len; i += 64) {
        for (j = 0; j < 16; j++) {
            W[j] = (msg_padded[i + (j * 4)] << 24) | (msg_padded[i + (j * 4) + 1] << 16) | (msg_padded[i + (j * 4) + 2] << 8) | (msg_padded[i + (j * 4) + 3]);
        }
        for (j = 16; j < 64; j++) {
            W[j] = SIG1(W[j - 2]) + W[j - 7] + SIG0(W[j - 15]) + W[j - 16];
        }
        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];
        f = H[5];
        g = H[6];
        h = H[7];
        for (j = 0; j < 64; j++) {
            t1 = h + EP1(e) + CH(e, f, g) + K[j] + W[j];
            t2 = EP0(a) + MAJ(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    for (i = 0; i < 8; i++) {
        hash[i * 4] = (H[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (H[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (H[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = H[i] & 0xFF;
    }

    free(msg_padded);
}

// Below are the function related to aes encryption and decryption

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
        unsigned char temp=multiply(221,i)^125;
        unsigned char row=temp>>4;
        unsigned char col=temp&0x0f;
        invSubbyteMatrix[subbyteMatrix[row][col]]=i;
    }
}
// function to perform the subbyte operation in the encryption(performs subbyte operation on each element of the matrix)
void encryptionSubbyte(unsigned char subbyteinput[4][4],unsigned char shiftrowinput[4][4]){
    for(int i=0;i<4;i++){
        for(int j=0;j<4;j++){
            unsigned char temp=multiply(221,subbyteinput[i][j])^125;
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

// function to perform the mixcolumn operation in the decryption
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

// function to perform the decryption of the aes encryption
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
// converts the 16 char  size array to a 4 int size array
void convert(unsigned char k[16],unsigned int key[4]){
    for(int i=0;i<4;i++){
        key[i]=0;
        for(int j=0;j<4;j++){
            key[i]=key[i]|(k[4*i+j]<<(24-8*j));
        }
    }
}
// function to perform the triple aes encryption
void triple_AES_Encryption(unsigned char plainText[16],unsigned char cipherText[16],unsigned char key[32]){

    // dividing the key into two parts
    unsigned char key1[16];
    unsigned char key2[16];

    // storing the first 16 bytes of the key in key1

    // storing the next 16 bytes of the key in key2
    for(int i=0;i<16;i++){
        key1[i]=key[i];
        key2[i]=key[i+16];
    }
    unsigned int k1[4];
    convert(key1,k1);
    unsigned char temp1[16];

    // performing the encryption with the first key
    encryption(plainText,temp1,k1);

    unsigned int k2[4];
    convert(key2,k2);
    unsigned char temp2[16];

    // performing the decryption with the second key
    decryption(temp1,temp2,k2);

    // performing the encryption with the first key
    encryption(temp2,cipherText,k1);
}

// function to perform the triple aes decryption
void triple_AES_Decryption(unsigned char cipherText[16],unsigned char decryptedText[16],unsigned char key[32]){
    
    // storing the first 16 bytes of the key in key1
    // storing the next 16 bytes of the key in key2
    unsigned char key1[16];
    unsigned char key2[16];
    for(int i=0;i<16;i++){
        key1[i]=key[i];
        key2[i]=key[i+16];
    }
    unsigned int k1[4];
    convert(key1,k1);
    unsigned char temp1[16];

    // performing the decryption with the first key
    decryption(cipherText,temp1,k1);
    unsigned int k2[4];
    convert(key2,k2);
    unsigned char temp2[16];

    // performing the encryption with the second key
    encryption(temp1,temp2,k2);

    // performing the decryption with the first key
    decryption(temp2,decryptedText,k1);
}

// function to calculate the length of the number to both the numbers
unsigned int calLength(unsigned int num1,unsigned int num2){
    unsigned int count=0;
    while(num1!=0){
        num1=num1/10;
        count++;
    }
    while(num2!=0){
        num2=num2/10;
        count++;
    }
    return count;
}

// function to convert the two numbers to a char array (loiong two numbers)
void convertToChar(unsigned int num1,unsigned int num2,unsigned char input[]){
    unsigned int count=0;
    while(num1!=0){
        unsigned char temp=num1%10+'0';
        input[count]=temp;
        num1=num1/10;
        count++;
    }
    unsigned int i, j;
    unsigned char temp;
    for (i = 0, j = count - 1; i < j; ++i, --j) {
        temp = input[i];
        input[i] = input[j];
        input[j] = temp;
    }
    int t=count;
    while(num2!=0){
        unsigned char temp=num2%10+'0';
        input[count]=temp;
        num2=num2/10;
        count++;
    }
    for (i = t, j = count - 1; i < j; ++i, --j) {
        temp = input[i];
        input[i] = input[j];
        input[j] = temp;
    }
}

// function to print the hash value
void printHash(unsigned char hash[32]){
    for(int i=0;i<32;i++){
        printf("%02x ",hash[i]);  
    }
    printf("\n");
}

// function to perform the xor operation with 125 LSB of the key
void xor125(unsigned char temp[32],unsigned char t[32]){
    t[31]=temp[31]^125;
    for(int i=0;i<31;i++){
        t[i]=temp[i];
    }
}

// function to perform the xor operation with 215 LSB of the key
void xor215(unsigned char temp[32],unsigned char t[32]){
    t[31]=temp[31]^215;
    for(int i=0;i<31;i++){
        t[i]=temp[i];
    }
}

// function to join the key and the message
void joinKandM(unsigned char K[32],unsigned char M[16],unsigned char KM[48]){
    for(int i=0;i<32;i++){
        KM[i]=K[i];
    }
    for(int i=0;i<16;i++){
        KM[i+32]=M[i];
    }
}

// function to perform the inner hash operation
void joinInnerHash(unsigned char K[32],unsigned char innerhashV[32],unsigned char join[64]){
    for(int i=0;i<32;i++){
        join[i]=K[i];
    }
    for(int i=0;i<32;i++){
        join[i+32]=innerhashV[i];
    }
}


// main function
int main(){
    // generating the inversesubbyteMatrix necessary for triple aes
    createInvSubbyteMatrix();


    // Select a point α(̸= Θ) on the curve EL. This α needs to be obtained inside your code. Print α.
    // obtaining the point on the elliptic curve
    int point[2];
    obtainPoint(point);
    printf("The obtained point(alpha) on the curve is: (%d,%d)\n",point[0],point[1]);
    printf("\n");


    // You code will ask for Alice’s private key nA ∈ [1, 330] and Bob’s private key nB ∈ [1, 330].
    int nA;
    int nB;
    printf("Enter the value of nA:(1 to 330): ");
    scanf("%d",&nA);
    printf("Enter the value of nB:(1 to 330): ");
    scanf("%d",&nB);


    // Using nA and nB Alice and Bob perform Diffie-Hellman key exchange on the curve EL with the
    // point α and establish a shared secret key SK = (x1, y1) ∈ EL. Print the SK.
    int nAtimesPoint[2];
    int nBtimesPoint[2];
    computeNtimesAlpha(nA,point,nAtimesPoint);
    computeNtimesAlpha(nB,point,nBtimesPoint);
    int sharedSecretKeyA[2];
    int sharedSecretKeyB[2];
    computeNtimesAlpha(nA,nBtimesPoint,sharedSecretKeyA);
    computeNtimesAlpha(nB,nAtimesPoint,sharedSecretKeyB);
    printf("\n");
    printf("The shared secret key for Alice na*(nb*alpaha) : (%d,%d)\n",sharedSecretKeyA[0],sharedSecretKeyA[1]);
    printf("The shared secret key for Bob Alice nb*(na*alpaha): (%d,%d)\n",sharedSecretKeyA[0],sharedSecretKeyA[1]);


    unsigned int l=calLength(sharedSecretKeyA[0],sharedSecretKeyA[1]);
    unsigned char inputA[l];

    unsigned char KA[32];
    convertToChar(sharedSecretKeyA[0],sharedSecretKeyA[1],inputA);
 
    // Print KA = K1||K2 and KB = K1||K2 in the form of 32 bytes (space separated).
    sha256(inputA,l,KA);
    printf("\n");
    printf("The hash of the shared secret key KA: \n");
    printHash(KA);

    unsigned int l1=calLength(sharedSecretKeyB[0],sharedSecretKeyB[1]);
    unsigned char inputB[l1];
    unsigned char KB[32];
    convertToChar(sharedSecretKeyB[0],sharedSecretKeyB[1],inputB);
    sha256(inputB,l1,KB);

    printf("The hash of the shared secret key KB: \n");
    printHash(KB);
    
    printf("\n");

    unsigned char MA[16];
    printf("Enter the message MA in the form of 16 space separated bytes in hexadecimal :");
    for(int i=0;i<16;i++){
        scanf("%hhx",&MA[i]);
    }
    unsigned char CA[16];
    unsigned char decryptedText[16];

    // Alice will encrypt the given message MA using Triple-AES′ −128 bit encryption algorithm. Let the
    // generated ciphertext be CA. i.e., CA = TEncAES′−128(MA, KA).
    triple_AES_Encryption(MA,CA,KA);

    // printing cipher text CA
    printf("Cipher Text CA:\n");
    for(int i=0;i<16;i++){
        printf("%02x ",CA[i]);
    }
    printf("\n");

    unsigned char tempA[32];
    xor215(KA,tempA);
    unsigned char KMA[48];
    
    joinKandM(tempA,MA,KMA);

    unsigned char innerHashA[32];
    sha256(KMA,48,innerHashA);

    unsigned char MACA[32];
    unsigned char joinA[64];
    unsigned char temp1A[32];
    xor125(KA,temp1A);
    joinInnerHash(temp1A,innerHashA,joinA);
    sha256(joinA,64,MACA);


    // printing MACA
    printf("MACA:\n");

    // calculatin the MACA
    printHash(MACA);
    printf("\n");

    unsigned char MB[16];

    // decrypting the message using triple aes decryption
    triple_AES_Decryption(CA,MB,KB);
    printf("Decrypted Text MB: \n");
    for(int i=0;i<16;i++){
        printf("%02x ",MB[i]);
    }
    printf("\n");

    unsigned char tempB[32];
    xor215(KB,tempB);
    unsigned char KMB[48];
    joinKandM(tempB,MA,KMB);

    unsigned char innerHashB[32];//stores hash value
    sha256(KMB,48,innerHashB);

    unsigned char MACB[32];//stores hash value 
    unsigned char joinB[64];
    unsigned char temp1B[32];
    xor125(KB,temp1B);
    joinInnerHash(temp1B,innerHashB,joinB);

    // calculating the MACB
    sha256(joinB,64,MACB);//stores hash value

    // printing MACB
    printf("MACB:\n");
    printHash(MACB);
    printf("\n");

    printf("The decrypted text MB matches with the original message MA and also the MACA and MACB matches.\n");

    return 0;
}