#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

const BIO_METHOD *BIO_f_base64(void);

struct Bytes_t {
    int length;
    size_t allocLength;
    char* bytes;
} typedef Bytes_t;

void set_bytes_from_hex(char *hex, Bytes_t *bytes);

void base64_encode(Bytes_t *bytes, char *encoded);

void* safe_malloc(size_t size);

Bytes_t create_bytes(size_t size);