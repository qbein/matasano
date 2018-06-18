#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

typedef struct ByteBuffer {
    int length;
    size_t capacity;
    char* bytes;
} ByteBuffer;

typedef struct CharCipher {
    double score;
    char cipher;
} CharCipher;

void bytes_from_hex(char *hex, ByteBuffer *bytes);

void bytes_from_char(char character, ByteBuffer *bytes);

void bytes_from_str(char *character, ByteBuffer *bytes);

void bytes_copy_to(ByteBuffer *src, ByteBuffer *dest);

void hex_from_bytes(ByteBuffer *input, char *hex);

void base64_encode_bytes(ByteBuffer *bytes, char *encoded);

void xor_bytes(ByteBuffer *input, ByteBuffer *xor);

void xor_char(ByteBuffer *input, char cipher);

void xor_str(ByteBuffer *input, char cipher[]);

long hamming_distance(char *a, char *b);

void* safe_malloc(size_t size);

ByteBuffer create_bytes(size_t size);

void free_bytes(ByteBuffer *bytes);

double score_bytes(ByteBuffer *bytes);

CharCipher find_xor_char(ByteBuffer *bytes);

void find_xor_key(ByteBuffer *bytes, char *key);