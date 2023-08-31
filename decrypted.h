#define BUFFER_SIZE 4096
int generates_key_iv(unsigned char* key,unsigned char *iv,const unsigned char *password);
int decryptFile(const char *inputFile, const char *outputFile);


