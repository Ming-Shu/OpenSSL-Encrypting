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

    if(!EVP_BytesToKey(cipher, EVP_md5(), salt,password, strlen(password), 1, key, iv)){
        fprintf(stderr, "EVP_BytesToKey failed\n");
        return 1;
    }

}

int decryptFile(const char *inputFile, const char *outputFile) {
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	
    FILE *inFile = fopen(inputFile, "rb");
    FILE *outFile = fopen(outputFile, "wb");
    int bytesRead, bytesWritten, finalBytesWritten;

	  int BlockSize = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    unsigned char inBuffer[BUFFER_SIZE];
    unsigned char outBuffer[BUFFER_SIZE+BlockSize];

   	generates_key_iv(key,iv,"1234");

    if (inFile == NULL || outFile == NULL) {
        perror("Failed to open file");
        return 1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	  EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    while ((bytesRead = fread(inBuffer, sizeof(unsigned char), BUFFER_SIZE , inFile)) > 0) {
        EVP_DecryptUpdate(ctx, outBuffer, &bytesWritten, inBuffer, bytesRead);
        fwrite(outBuffer, sizeof(unsigned char), bytesWritten, outFile);
    }

    EVP_DecryptFinal_ex(ctx, outBuffer, &finalBytesWritten);
    fwrite(outBuffer,sizeof(unsigned char), finalBytesWritten, outFile);
    EVP_CIPHER_CTX_free(ctx);
	  EVP_cleanup();
    fclose(inFile);
    fclose(outFile);

    return 0;
}

int main()
{
    const char *encryptedFile = "aaa.bin";
    const char *decryptedFile = "decrypted.txt";

    // Dencrypt the file
    if(decryptFile(encryptedFile,decryptedFile)){
        fprintf(stderr, "decryption failed\n");
        return 1;
    }
    printf("File decrypted: %s\n",decryptedFile);
    return 0;
}
