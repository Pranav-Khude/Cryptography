/*Name: Khude Pranav Eknath
Student ID: 202151077
Lab Assignment 1
Introduction to Cryptography and Network Security Laboratory*/

/*For the given assignment value of a and b is 11 and 15 respectively.
So, the value of ainv is 11.
*/

#include <stdio.h>
#include <string.h>
// Defining the global array
char globalCharArray[30] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
                            'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
                            'U', 'V', 'W', 'X', 'Y', 'Z', ',', '.', '?', ';'};
// Function to create the key 6*5 table for Playfair Cipher
void createKeyTable(char key[100], char keyTable[6][5]){
    // creating a visited array to keep track of the characters that are already used
    char Visited[30];
    for(int i=0;i<30;i++){
        Visited[i] = 0;
    }
    int k = 0;
    // Filling the key in the key table
    for(int i=0;i<strlen(key);i++){
        for(int j=0;j<30;j++){
            if(key[i] == globalCharArray[j] && Visited[j] == 0){
                keyTable[k/5][k%5] = key[i];
                Visited[j] = 1;
                k++;
                break;
            }
        }
    }
    // Filling the remaining characters in the key table
    for(int i=0;i<30;i++){
        if(Visited[i] == 0){
            keyTable[k/5][k%5] = globalCharArray[i];
            k++;
        }
    }
    // Printing the Key table
    printf("Key Table: \n");
    for(int i=0;i<6;i++){
        for(int j=0;j<5;j++){
            printf("%c ", keyTable[i][j]);
        }
        printf("\n");
    }

}
// Function to create the digram
void createDigram(char digram[100]) {
    int length = strlen(digram);
    for (int i = 0; i < length - 1; i+=2) {
        if (digram[i] == digram[i + 1]) {
            for (int j = length; j > i + 1; j--) {
                digram[j] = digram[j - 1];
            }
            length++; // Increment length after insertion
            if(digram[i]=='X'){ //if we have consecutive X then to handle the condition of similar characters we add Y in between.
                digram[i + 1] = 'Y';
            }else{
                digram[i + 1] = 'X';
            }
        }
    }
    // to solve the issue of odd length digram
    if (length % 2 != 0) {
        if(digram[length-1]!='X'){
            digram[length] = 'X';
        }else{
            digram[length] = 'Y';//if at the odd length we have X at the end position we add Y instead of X . 
        }
        length++; // Increment length after insertion
    }
    digram[length] = '\0';
    printf("PlainText according to the rule of the Playfair cipher: %s\n", digram);
}
// Function to encrypt the plain text using Playfair Cipher
void encryptPlayfair(char digram[100], char keyTable[6][5],char CipherText[100]){
    int k = 0;
    // Encrypting the digram
    for(int i=0;i<strlen(digram);i+=2){
        int x1, y1, x2, y2;
        for(int j=0;j<6;j++){
            for(int k=0;k<5;k++){
                if(digram[i] == keyTable[j][k]){
                    x1 = j;
                    y1 = k;
                }
                if(digram[i+1] == keyTable[j][k]){
                    x2 = j;
                    y2 = k;
                }
            }
        }
        // same row condition
        if(x1 == x2){
            CipherText[k] = keyTable[x1][(y1+1)%5];
            CipherText[k+1] = keyTable[x2][(y2+1)%5];
        }
        // same column condition 
        else if(y1 == y2){
            CipherText[k] = keyTable[(x1+1)%6][y1];
            CipherText[k+1] = keyTable[(x2+1)%6][y2];
        }
        // different row and column condition
        else{
            CipherText[k] = keyTable[x1][y2];
            CipherText[k+1] = keyTable[x2][y1];
        }
        k+=2;
    }
    CipherText[k] = '\0';  
    printf("Cipher Text1 after Playfair encryption : %s\n", CipherText);
}
// Function to decrypt the cipher text using Playfair Cipher
void decryptPlayfair(char keyTable[6][5],char CipherText[100],char DecryptedText[100]){
    int f=0;
    for(int i=0;i<strlen(CipherText);i+=2){
        int x1, y1, x2, y2;
        for(int j=0;j<6;j++){
            for(int k=0;k<5;k++){
                if(CipherText[i] == keyTable[j][k]){
                    x1 = j;
                    y1 = k;
                }
                if(CipherText[i+1] == keyTable[j][k]){
                    x2 = j;
                    y2 = k;
                }
            }
        }
        // same row condition
        if(x1 == x2){
            DecryptedText[f] = keyTable[x1][(y1-1+5)%5];
            DecryptedText[f+1] = keyTable[x2][(y2-1+5)%5];
        }
        // same column condition
        else if(y1 == y2){
            DecryptedText[f] = keyTable[(x1-1+6)%6][y1];
            DecryptedText[f+1] = keyTable[(x2-1+6)%6][y2];
        }
        // different row and column condition
        else{
            DecryptedText[f] = keyTable[x1][y2];
            DecryptedText[f+1] = keyTable[x2][y1];
        }
        f+=2;
    }
    DecryptedText[strlen(CipherText)] = '\0';
    printf("Decrypted Text1 after Decrypting Playfair Cipher: %s\n", DecryptedText);
}
// Function to encrypt the plain text using Affine Cipher
void encryptAffineCipher(char PlainText2[100],int a,int b,char CipherText2[100]){
    for(int i=0;i<strlen(PlainText2);i++){
        int x=0;
        for(int j=0;j<30;j++){
            if(PlainText2[i]==globalCharArray[j]){
                x=j;
                break;
            }
        }
        int temp=(a*x+b)%30;
        CipherText2[i]=globalCharArray[temp];
    }
    CipherText2[strlen(PlainText2)] = '\0';
    printf("Cipher Text2 after Affine Cipher Encryption: %s\n",CipherText2);
}
// Function to decrypt the cipher text using Affine Cipher
void decryptAffineCipher(char CipherText2[100],int ainv,int b,char DecryptedText2[100]){
    for(int i=0;i<strlen(CipherText2);i++){
        int y=0;
        for(int j=0;j<30;j++){
            if(CipherText2[i]==globalCharArray[j]){
                y=j;
                break;
            }
        }
        int temp=(ainv*(y-b+30))%30;
        DecryptedText2[i]=globalCharArray[temp];
    }
    DecryptedText2[strlen(CipherText2)] = '\0';
    printf("Decrypted Text2 after Decrypting Affine Cipher: %s\n",DecryptedText2);
}
// Function to encrypt the plain text using Shift Cipher
void encryptShiftCipher(char PlainText3[100],int k,char CipherText3[100]){
    for(int i=0;i<strlen(PlainText3);i++){
        int x=0;
        for(int j=0;j<30;j++){
            if(PlainText3[i]==globalCharArray[j]){
                x=j;
                break;
            }
        }
        int temp=(x+k)%30;
        CipherText3[i]=globalCharArray[temp];
    }
    CipherText3[strlen(PlainText3)] = '\0';
    printf("Cipher Text3 after Shift Cipher Encryption: %s\n",CipherText3);
}
// Function to decrypt the cipher text using Shift Cipher
void decryptShiftCipher(char CipherText3[100],int k,char DecryptedText3[100]){
    for(int i=0;i<strlen(CipherText3);i++){
        int y=0;
        for(int j=0;j<30;j++){
            if(CipherText3[i]==globalCharArray[j]){
                y=j;
                break;
            }
        }
        int temp=(y-k+30)%30;
        DecryptedText3[i]=globalCharArray[temp];
    }
    DecryptedText3[strlen(CipherText3)] = '\0';
    printf("Decrypted Text3 after Decrypting Shift Cipher: %s\n",DecryptedText3);
}
int main(){
    char PlainText[100];
    // Taking the input from the user
    printf("Enter the plain text: ");
    scanf("%s", PlainText);

    char digram[100];
    strcpy(digram, PlainText);
    createDigram(digram);

    // Taking the key from the user
    printf("Enter the key for Playfair Cipher: ");
    char key[100];
    scanf("%s", key);

    // Creating the key table
    char keyTable[6][5];
    createKeyTable(key, keyTable);

    // Encrypting the plain text using Playfair Cipher
    char CipherText[100];
    encryptPlayfair(digram, keyTable, CipherText);

    // Encrypting using Affine Cipher
    char CipherText2[100];
    encryptAffineCipher(CipherText,11,15,CipherText2);

    // Encrypting using Shift Cipher
    printf("Enter the key for Shift Cipher: ");
    int keyShift;
    scanf("%d", &keyShift);
    char CipherText3[100];
    encryptShiftCipher(CipherText2,keyShift,CipherText3);

    // Decrypting the cipher text using Shift Cipher
    char DecryptedText3[100];
    decryptShiftCipher(CipherText3,keyShift,DecryptedText3);

    // Decrypting the cipher text using Affine Cipher
    char DecryptedText2[100];
    decryptAffineCipher(DecryptedText3,11,15,DecryptedText2);

    // Decrypting the cipher text using Playfair Cipher
    char DecryptedText[100];
    decryptPlayfair(keyTable, DecryptedText2, DecryptedText);
    return 0;
}