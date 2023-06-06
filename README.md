# OpenSSL-Encrypting
Encrypting  a file(.txt) encrypting using command /decrypting it with AES256CBC using EVP api of openssl

openssl version :OpenSSL 1.0.1f 6 Jan 2014
file:input.txt
password:1234

The encrypting command:
    openssl aes-256-cbc -nosalt -e -p -k 1234 -in input.txt -out aaa.bin
    
Compile command:
    gcc decrypted.c -lcrypto -o decrypted   
