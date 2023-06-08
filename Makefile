OBJ = decrypted.c

all: target clean

target: decrypted.o
        gcc -o decrypted decrypted.o -lcrypto
decrypted.o:$(OBJ) encrypted
        gcc -c $(OBJ)
.PHONY: encrypted
encrypted:
        openssl aes-256-cbc -nosalt -e -p -k 1234 -in input.txt -out aaa.bin
.PHONY: clean
clean:
        rm -f decrypted.o


