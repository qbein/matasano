#include <stdio.h>
#include <stdlib.h>

struct Bytes_t {
    unsigned int length;
    size_t allocLength;
    unsigned char* bytes;
} typedef Bytes_t;

void set_bytes_from_hex(char *hex, Bytes_t *bytes);

void* safe_malloc(size_t size);

Bytes_t create_bytes(size_t size);