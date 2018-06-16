#include "crypto.h"

void* safe_malloc(size_t size) {
    void* buffer;
    buffer = (void*)malloc(size);
    if(buffer == NULL) {
        printf("Could not allocate memory");
        exit(1);
    }
    return buffer;
}

Bytes_t create_bytes(size_t size) {
    struct Bytes_t bytes = { 0, size, (unsigned char*)safe_malloc(size) };
    return bytes;
}

void set_bytes_from_hex(char* hex, Bytes_t *bytes) {
    char *ptr;
    bytes->length = 0;
    for(ptr = hex; *ptr != '\0'; ptr+=2) {
        char byteAsHex[3] = { *ptr, *(ptr+1), '\0' };
        bytes->bytes[bytes->length++] = strtol(byteAsHex, NULL, 16);
    }
}