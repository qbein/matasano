#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <assert.h>
#include "crypto.h"
#include "ascii.h"

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
    memset(bytes.bytes, 0, size);
    return bytes;
}

void free_bytes(Bytes_t *bytes) {
    free(bytes->bytes);
}

void bytes_from_hex(char* hex, Bytes_t *bytes) {
    memset(bytes->bytes, 0, bytes->capacity);
    bytes->length = 0;
    for(int i=0; i<bytes->capacity-3; i+=2) {
        if(*(hex+i)==0||*(hex+i+1)==0) break;
        char byteAsHex[3] = { *(hex+i), *(hex+i+1), 0 };
        bytes->bytes[bytes->length++] = strtol(byteAsHex, NULL, 16);
    }
}

void bytes_from_str(char *string, Bytes_t *bytes) {
    memset(bytes->bytes, 0, bytes->capacity);
    bytes->length = strlen(string);
    if(bytes->length>bytes->capacity) {
        bytes->length = bytes->capacity-1;
    }
    strncpy(bytes->bytes, string, bytes->length);
}

void bytes_from_char(char character, Bytes_t *bytes) {
    memset(bytes->bytes, 0, bytes->capacity);
    bytes->bytes[0] = character;
    bytes->length = 1;
}

void copy_bytes(Bytes_t *src, Bytes_t *dest) {
    assert(src->capacity == dest->capacity);
    memset(dest->bytes, 0, dest->capacity);
    dest->length = src->length;
    memcpy(dest->bytes, src->bytes, src->length);
}

void hex_from_bytes(Bytes_t *input, char *hex) {
    for(int i=0; i<input->length; i++) {
        sprintf(&hex[i*2], "%02x", (int)input->bytes[i]);
    }
}

void xor_bytes(Bytes_t *input, Bytes_t *xor, Bytes_t *output) {
    assert(input->capacity == output->capacity);
    for(int i=0; i<input->length; i++) {
        output->bytes[i] = input->bytes[i]^xor->bytes[i%xor->length];
    }
    output->length = input->length;
}

void xor_char(Bytes_t *input, char cipher, Bytes_t *output) {
    char cipher_str[] = { cipher, 0 };
    xor_str(input, cipher_str, output);
}

void xor_str(Bytes_t *input, char cipher[], Bytes_t *output) {
    size_t len = strlen(cipher);
    Bytes_t cipher_bytes = create_bytes(len+1);
    bytes_from_str(cipher, &cipher_bytes);
    xor_bytes(input, &cipher_bytes, output);
    free_bytes(&cipher_bytes);
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

double letter_freq_score(Bytes_t *bytes) {
    double score = 0;
    for(int i=0; bytes->length; i++) {
        char letter = bytes->bytes[i];
        if(letter == 0) break;

        if(letter == 0x20) {
            score += LetterFreq[SPACE];
            continue;
        }
        if((letter >= 0x41 && letter <= 0x5a)
            || (letter >= 0x61 && letter <= 0x7a))
        {
            if(letter >= 0x61) letter -= 0x20;

            if(letter == 'A') score += LetterFreq[A];
            else if(letter == 'B') score += LetterFreq[B];
            else if(letter == 'C') score += LetterFreq[C];
            else if(letter == 'D') score += LetterFreq[D];
            else if(letter == 'E') score += LetterFreq[E];
            else if(letter == 'F') score += LetterFreq[F];
            else if(letter == 'G') score += LetterFreq[G];
            else if(letter == 'H') score += LetterFreq[H];
            else if(letter == 'I') score += LetterFreq[I];
            else if(letter == 'J') score += LetterFreq[J];
            else if(letter == 'K') score += LetterFreq[K];
            else if(letter == 'L') score += LetterFreq[L];
            else if(letter == 'M') score += LetterFreq[M];
            else if(letter == 'N') score += LetterFreq[N];
            else if(letter == 'O') score += LetterFreq[O];
            else if(letter == 'P') score += LetterFreq[P];
            else if(letter == 'Q') score += LetterFreq[Q];
            else if(letter == 'R') score += LetterFreq[R];
            else if(letter == 'S') score += LetterFreq[S];
            else if(letter == 'T') score += LetterFreq[T];
            else if(letter == 'U') score += LetterFreq[U];
            else if(letter == 'V') score += LetterFreq[V];
            else if(letter == 'W') score += LetterFreq[W];
            else if(letter == 'X') score += LetterFreq[X];
            else if(letter == 'Y') score += LetterFreq[Y];
            else if(letter == 'Z') score += LetterFreq[Z];
            continue;
        }
        else if((letter >= 0x21 && letter <= 0x2f)
            || (letter >= 0x3a && letter <= 0x40)
            || (letter >= 0x5b && letter <= 0x60)
            || (letter >= 0x7b && letter <= 0x7e))
        {
            score += 2;
            continue;
        }
    }
    return score;
}

Char_cipher_t find_xor_char(Bytes_t *bytes) {
    struct Char_cipher_t highscore = { 0, 0 };
    Bytes_t output = create_bytes(bytes->capacity);

    for(int i=1; i<255; i++) {
        xor_char(bytes, (char)i, &output);

        double s = letter_freq_score(&output);
        if(s>highscore.score) {
            highscore.score = s;
            highscore.cipher = (char)i;
        }
    }

    free_bytes(&output);

    return highscore;
}

long hamming_distance(char *a, char *b) {
    size_t size_a = strlen(a);
    size_t size_b = strlen(b);
    size_t len = size_a > size_b ? size_b : size_a;
    // If strings differ in length, ass 8 bits for each missing letter
    long distance = (size_a > size_b ? size_a - size_b : size_b - size_a)*8;
    for(int i=0; i<len; i++) {
        int byte_a = (int)a[i];
        int byte_b = (int)b[i];
        for(int j=0; j<8; j++) {
            if((byte_a&1) != (byte_b&1)) distance++;
            byte_a >>= 1;
            byte_b >>= 1;
        }
    }
    return distance;
}