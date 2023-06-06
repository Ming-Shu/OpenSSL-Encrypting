#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#define BUFFER_SIZE 4096

int generates_key_iv(unsigned char* key,unsigned char *iv,const unsigned char *password)
{
     const EVP_CIPHER *cipher;
     const EVP_MD *dgst = NULL;
     const unsigned char *salt = NULL;
     int i;

    OpenSSL_add_all_algorithms();

    cipher = EVP_get_cipherbyname("aes-256-cbc");
    if(!cipher) { 
       fprintf(stderr, "no such cipher\n"); 
       return 1; 
    }

    dgst=EVP_get_digestbyname("md5");
    if(!dgst) { 
       fprintf(stderr, "no such digest\n"); 
       return 1; 
    }

    if(!EVP_BytesToKey(cipher, dgst, salt,password, strlen(password), 1, key, iv)){
        fprintf(stderr, "EVP_BytesToKey failed\n");
        return 1;
    }

    printf("Key: "); for(i=0; i<cipher->key_len; ++i) { printf("%02x", key[i]); } printf("\n");
    printf("IV: "); for(i=0; i<cipher->iv_len; ++i) { printf("%02x", iv[i]); } printf("\n");


} 

int decryptFile(const char *inputFile, const char *outputFile, const unsigned char* key, const unsigned char *iv) {
    FILE *inFile = fopen(inputFile, "rb");
    FILE *outFile = fopen(outputFile, "wb");
    unsigned char inBuffer[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char outBuffer[BUFFER_SIZE];
    int bytesRead, bytesWritten, finalBytesWritten;



    if (inFile == NULL || outFile == NULL) {
        perror("Failed to open file");
        return 0;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    while ((bytesRead = fread(inBuffer, 1, BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH, inFile)) > 0) {
        EVP_DecryptUpdate(ctx, outBuffer, &bytesWritten, inBuffer, bytesRead);
        fwrite(outBuffer, 1, bytesWritten, outFile);
    }

    EVP_DecryptFinal_ex(ctx, outBuffer, &finalBytesWritten);
    fwrite(outBuffer, 1, finalBytesWritten, outFile);

    EVP_CIPHER_CTX_free(ctx);
    fclose(inFile);
    fclose(outFile);

    return 0;
}

int main()
{
    const char *encryptedFile = "aaa.bin";
    const char *decryptedFile = "decrypted.txt";
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    const char *password = "1234";

    //Generates key and iv
    generates_key_iv(key,iv,password);

    // Dencrypt the file
    if(decryptFile(encryptedFile,decryptedFile, key, iv)){
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }
    printf("File decrypted: %s\n",decryptedFile);
    return 0;
}

