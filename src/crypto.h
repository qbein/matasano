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

void bytes_from_hex(char *hex, Bytes_t *bytes);

void hex_from_bytes(Bytes_t *input, char *hex);

void base64_encode(Bytes_t *bytes, char *encoded);

void xor_encrypt(Bytes_t *input, Bytes_t *xor, Bytes_t *output);

void* safe_malloc(size_t size);

Bytes_t create_bytes(size_t size);

void free_bytes(Bytes_t *bytes);