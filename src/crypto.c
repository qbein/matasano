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

ByteBuffer create_bytes(size_t size) {
    ByteBuffer bytes = { 0, size, (char*)safe_malloc(size) };
    memset(bytes.bytes, 0, size);
    return bytes;
}

void free_bytes(ByteBuffer *bytes) {
    free(bytes->bytes);
}

void bytes_from_hex(char* hex, ByteBuffer *bytes) {
    memset(bytes->bytes, 0, bytes->capacity);
    bytes->length = 0;
    for(int i=0; i<bytes->capacity-3; i+=2) {
        if(*(hex+i)==0||*(hex+i+1)==0) break;
        char byteAsHex[3] = { *(hex+i), *(hex+i+1), 0 };
        bytes->bytes[bytes->length++] = strtol(byteAsHex, NULL, 16);
    }
}

void bytes_from_str(char *string, ByteBuffer *bytes) {
    memset(bytes->bytes, 0, bytes->capacity);
    bytes->length = strlen(string);
    if(bytes->length>bytes->capacity) {
        bytes->length = bytes->capacity-1;
    }
    strncpy(bytes->bytes, string, bytes->length);
}

void bytes_from_char(char character, ByteBuffer *bytes) {
    memset(bytes->bytes, 0, bytes->capacity);
    bytes->bytes[0] = character;
    bytes->length = 1;
}

void bytes_copy_to(ByteBuffer *src, ByteBuffer *dest) {
    assert(src->capacity == dest->capacity);
    memset(dest->bytes, 0, dest->capacity);
    dest->length = src->length;
    memcpy(dest->bytes, src->bytes, src->length);
}

void hex_from_bytes(ByteBuffer *input, char *hex) {
    for(int i=0; i<input->length; i++) {
        sprintf(&hex[i*2], "%02x", (int)input->bytes[i]);
    }
}

void xor_bytes(ByteBuffer *input, ByteBuffer *xor) {
    for(int i=0; i<input->length; i++) {
        input->bytes[i] = input->bytes[i]^xor->bytes[i%xor->length];
    }
}

void xor_char(ByteBuffer *input, char cipher) {
    char cipher_str[] = { cipher, 0 };
    xor_str(input, cipher_str);
}

void xor_str(ByteBuffer *input, char cipher[]) {
    size_t len = strlen(cipher);
    ByteBuffer cipher_bytes = create_bytes(len+1);
    bytes_from_str(cipher, &cipher_bytes);
    xor_bytes(input, &cipher_bytes);
    free_bytes(&cipher_bytes);
}

void base64_encode_bytes( ByteBuffer *bytes, char *encoded) {
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

double score_bytes(ByteBuffer *bytes) {
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

CharCipher find_xor_char(ByteBuffer *bytes) {
    CharCipher highscore = { 0, 0 };
    ByteBuffer tmp = create_bytes(bytes->capacity);

    for(int i=1; i<255; i++) {
        bytes_copy_to(bytes, &tmp);
        xor_char(&tmp, (char)i);

        double s = score_bytes(&tmp);
        if(s>highscore.score) {
            highscore.score = s;
            highscore.cipher = (char)i;
        }
    }

    free_bytes(&tmp);

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