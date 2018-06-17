#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

const BIO_METHOD *BIO_f_base64(void);

struct Bytes_t {
    int length;
    size_t capacity;
    char* bytes;
} typedef Bytes_t;

struct Char_cipher_t {
    double score;
    char cipher;
} typedef Char_cipher_t;

void bytes_from_hex(char *hex, Bytes_t *bytes);

void bytes_from_char(char character, Bytes_t *bytes);

void bytes_from_str(char *character, Bytes_t *bytes);

void copy_bytes(Bytes_t *src, Bytes_t *dest);

void hex_from_bytes(Bytes_t *input, char *hex);

void base64_encode(Bytes_t *bytes, char *encoded);

void xor_bytes(Bytes_t *input, Bytes_t *xor, Bytes_t *output);

void xor_char(Bytes_t *input, char cipher, Bytes_t *output);

void xor_str(Bytes_t *input, char cipher[], Bytes_t *output);

long hamming_distance(char *a, char *b);

void* safe_malloc(size_t size);

Bytes_t create_bytes(size_t size);

void free_bytes(Bytes_t *bytes);

double letter_freq_score(Bytes_t *bytes);

Char_cipher_t find_xor_char(Bytes_t *bytes);