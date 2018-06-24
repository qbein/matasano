#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

typedef struct ByteBuffer {
    size_t length;
    size_t capacity;
    char* bytes;
} ByteBuffer;

typedef struct CharCipher {
    double score;
    char cipher;
} CharCipher;

ByteBuffer create_bytes(size_t size);

ByteBuffer bytes_from_hex(char *hex);

ByteBuffer bytes_from_char(char character);

ByteBuffer bytes_from_str(char *str);

ByteBuffer bytes_from_file(char *file);

void bytes_copy_to(ByteBuffer src, ByteBuffer *dest);

char* hex_from_bytes(ByteBuffer input);

ByteBuffer base64_encode_bytes(ByteBuffer bytes);

ByteBuffer base64_decode_bytes(ByteBuffer encoded);

void xor_bytes(ByteBuffer *input, ByteBuffer xor);

void xor_char(ByteBuffer *input, char cipher);

void xor_str(ByteBuffer *input, char *cipher);

long hamming_distance(char *a, size_t size_a, char *b, size_t size_b);

void* safe_malloc(size_t size);

void resize_bytes(ByteBuffer *bytes);

void resize_bytes_to(ByteBuffer *bytes, size_t capacity);

void free_bytes(ByteBuffer *bytes);

float score_bytes(ByteBuffer bytes);

CharCipher find_xor_char(ByteBuffer bytes, int verbose);

char* find_xor_key(ByteBuffer bytes);

int find_keysize(ByteBuffer bytes, int verbose);

void hex_dump(unsigned char *bytes, int len);