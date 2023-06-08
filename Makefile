OBJ = decrypted.c

all: decrypted.o
        gcc -o decrypted decrypted.o -lcrypto
decrypted.o:$(OBJ) encrypted
        gcc -c $(OBJ)
.PHONY: encrypted clean
encrypted:
        openssl aes-256-cbc -nosalt -e -p -k 1234 -in input.txt -out encrypted.bin
.PHONY: clean
clean:
        rm -f decrypted.o
