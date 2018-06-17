#include <string.h>
#include <stdio.h>
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
    memset(bytes.bytes, 0, bytes.capacity);
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

void bytes_from_char(char character, Bytes_t *bytes) {
    bytes->bytes[0] = character;
    bytes->length = 1;
}

void hex_from_bytes(Bytes_t *input, char *hex) {
    for(int i=0; i<input->length; i++) {
        sprintf(&hex[i*2], "%x", (int)input->bytes[i]);
    }
}

void xor_encrypt(Bytes_t *input, Bytes_t *xor, Bytes_t *output) {
    assert(input->capacity == output->capacity);
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

double str_letter_freq_score(Bytes_t *bytes) {
    double score = 0;
    for(int i=0; bytes->length; i++) {
        char letter = bytes->bytes[i];
        if(letter == '\0') break;

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

char find_xor_char(Bytes_t *bytes) {
    struct score {
        double score;
        char character;
    };
    struct score highscore = { 0, '\0' };
    for(int i=1; i<255; i++) {
        Bytes_t xor = create_bytes(1);
        xor.length = 1;
        xor.bytes[0] = (char)i;
        Bytes_t output = create_bytes(bytes->capacity);
        xor_encrypt(bytes, &xor, &output);

        double s = str_letter_freq_score(&output);
        if(s>highscore.score) {
            highscore.score = s;
            highscore.character = (char)i;
        }
    }
    return highscore.character;
}