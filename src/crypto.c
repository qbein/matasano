#include <string.h>
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <assert.h>
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
    struct Bytes_t bytes = { 0, size, (char*)safe_malloc(size) };
    memset(bytes.bytes, 0, bytes.allocLength);
    return bytes;
}

void free_bytes(Bytes_t *bytes) {
    free(bytes->bytes);
}

void bytes_from_hex(char* hex, Bytes_t *bytes) {
    char *ptr;
    bytes->length = 0;
    for(ptr = hex; *ptr != '\0'; ptr+=2) {
        char byteAsHex[3] = { *ptr, *(ptr+1), '\0' };
        bytes->bytes[bytes->length++] = strtol(byteAsHex, NULL, 16);
    }
}

void hex_from_bytes(Bytes_t *input, char *hex) {
    for(int i=0; i<input->length; i++) {
        sprintf(&hex[i*2], "%x", (int)input->bytes[i]);
    }
}

void xor_encrypt(Bytes_t *input, Bytes_t *xor, Bytes_t *output) {
    assert(input->allocLength == output->allocLength);
    for(int i=0; i<input->length; i++) {
        output->bytes[i] = input->bytes[i]^xor->bytes[i%xor->length];
    }
    output->length = input->length;
}

void base64_encode(Bytes_t *bytes, char *encoded) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    BIO_write(b64, bytes->bytes, bytes->length);
    BIO_flush(b64);

    char *output;
    int outputlen = BIO_get_mem_data(mem, &output);

    strncpy(encoded, output, outputlen);

    BIO_free_all(b64);
}