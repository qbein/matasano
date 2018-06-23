#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <assert.h>
#include <limits.h>
#include "crypto.h"
#include "letterfreq.h"

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
    ByteBuffer bytes = { 0, size, (char*)safe_malloc(size+1) };
    memset(bytes.bytes, 0, size+1);
    return bytes;
}

void resize_bytes(ByteBuffer *bytes) {
    size_t size = bytes->capacity<<1;
    bytes->bytes = realloc(bytes->bytes, size);
    memset(&bytes->bytes[bytes->length], 0, bytes->capacity-bytes->length);
    bytes->capacity = size;
}

void resize_bytes_to(ByteBuffer *bytes, size_t capacity) {
    assert(capacity >= bytes->capacity);
    if(capacity == bytes->capacity) return;
    bytes->bytes = realloc(bytes->bytes, capacity);
    memset(&bytes->bytes[bytes->length], 0, bytes->capacity-bytes->length);
    bytes->capacity = capacity;
}

void free_bytes(ByteBuffer *bytes) {
    free(bytes->bytes);
}

ByteBuffer bytes_from_hex(char *hex) {
    ByteBuffer bytes = create_bytes(strlen(hex)/2+1);

    for(int i=0; i<bytes.capacity; i++) {
        if(*(hex+i*2)==0||*(hex+i+1*2)==0) break;
        char byteAsHex[3] = { *(hex+i*2), *(hex+i*2+1), 0 };
        bytes.bytes[bytes.length++] = strtol(byteAsHex, NULL, 16);
    }

    return bytes;
}

ByteBuffer bytes_from_str(char *str) {
    ByteBuffer bytes = create_bytes(strlen(str)+1);
    bytes.length = bytes.capacity-1;
    strncpy(bytes.bytes, str, bytes.length);
    return bytes;
}

ByteBuffer bytes_from_char(char character) {
    ByteBuffer bytes = create_bytes(1);
    bytes.bytes[0] = character;
    return bytes;
}

ByteBuffer bytes_from_file(char *file) {
    ByteBuffer bytes = create_bytes(1024);
    FILE *fp = fopen(file, "r");
    size_t i = 0;
    while(1) {
        i = fread(&bytes.bytes[bytes.length], 1, 1024, fp);
        bytes.length += i;
        if(i < 1024) break;
        if(bytes.capacity<(bytes.length+1024)) {
            resize_bytes(&bytes);
        }
    };
    fclose(fp);
    return bytes;
}

void bytes_copy_to(ByteBuffer src, ByteBuffer *dest) {
    assert(src.capacity == dest->capacity);
    memset(dest->bytes, 0, dest->capacity);
    dest->length = src.length;
    memcpy(dest->bytes, src.bytes, src.length);
}

char* hex_from_bytes(ByteBuffer input) {
    char *hex = malloc(sizeof(char)*input.length+1);
    int i;
    for(i=0; i<input.length; i++) {
        sprintf(&hex[i*2], "%02x", (char)input.bytes[i]);
    }
    hex[i*2]=0;
    return hex;
}

void xor_bytes(ByteBuffer *input, ByteBuffer xor) {
    for(int i=0; i<input->length; i++) {
        input->bytes[i] = xor.length>0
            ? input->bytes[i]^xor.bytes[i%xor.length]
            : input->bytes[i];
    }
}

void xor_char(ByteBuffer *input, char cipher) {
    char cipher_str[] = { cipher, 0 };
    xor_str(input, cipher_str);
}

void xor_str(ByteBuffer *input, char cipher[]) {
    ByteBuffer cipher_bytes = bytes_from_str(cipher);
    xor_bytes(input, cipher_bytes);
    input->bytes[input->length] = 0;
}

ByteBuffer base64_encode_bytes(ByteBuffer *in) {
    ByteBuffer out = create_bytes(1024);
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    BIO_write(b64, in->bytes, in->length);
    BIO_flush(b64);

    char *output;
    int outputlen = BIO_get_mem_data(mem, &output);

    while(out.capacity<outputlen) {
        resize_bytes(&out);
    }
    strncpy(out.bytes, output, outputlen);
    out.length = outputlen;

    BIO_free_all(mem);

    return out;
}

ByteBuffer base64_decode_bytes(ByteBuffer *in) {
    ByteBuffer out = create_bytes(1024);
    char tmp[in->length];
    // Strip all non-base64 characters
    int j=0;
    for(size_t i=0; i<in->length; i++) {
        if((in->bytes[i] >= 'A' && in->bytes[i] <= 'Z')
            || (in->bytes[i] >= 'a' && in->bytes[i] <= 'z')
            || (in->bytes[i] >= '0' && in->bytes[i] <= '9')
            || in->bytes[i] == '='
            || in->bytes[i] == '+'
            || in->bytes[i] == '/') {
                tmp[j++] = in->bytes[i];
            }
    }
    tmp[j++] = '\0';

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf(&tmp[0], j);
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    out.length = BIO_read(bmem, out.bytes, j);

    BIO_free_all(bmem);
    return out;
}

float score_bytes(ByteBuffer bytes) {
    float score = 0;
    size_t i;
    for(i=0; bytes.length; i++) {
        char letter = bytes.bytes[i];
        if(letter == 0) break;

        if(letter == ' ') {
            score += LetterFreq[SPACE];
        }
        else if((letter >= 'A' && letter <= 'Z')
            || (letter >= 'a' && letter <= 'z'))
        {
            if(letter > 'Z') letter -= 0x20;

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
        }
        else if((letter >= 0x21 && letter <= 0x2f)
            || (letter >= 0x3a && letter <= 0x40)
            || (letter >= 0x5b && letter <= 0x60)
            || (letter >= 0x7b && letter <= 0x7e))
        {
            score += 2;
        }
        else {
            score -= 10;
        }
    }

    return score / bytes.length;
}

CharCipher find_xor_char(ByteBuffer bytes, int verbose) {
    CharCipher highscore = { -1, 0 };
    ByteBuffer tmp = create_bytes(bytes.capacity);

    if(verbose == 1)
        printf("Finding xor char:\n");

    for(int i=1; i<255; i++) {
        bytes_copy_to(bytes, &tmp);
        xor_char(&tmp, (char)i);
        float s = score_bytes(tmp);
        if(verbose)
            printf("  -> hex: %02x / %c, score: %f", i, (char)i, s);
        if(s>highscore.score) {
            highscore.score = s;
            highscore.cipher = (char)i;

            if(verbose == 1)
                printf("  -> New best match!");
        }
        if(verbose == 1)
            printf("\n");
    }

    free_bytes(&tmp);

    return highscore;
}

char* find_xor_key(ByteBuffer bytes) {
    int keysize = find_keysize(bytes, 0);
    char *out = malloc(sizeof(char)*keysize+1);
    ByteBuffer segment = create_bytes(bytes.length/keysize+1);

    for(int i=0; i<keysize; i++) {
        segment.length = 0;
        int j=i;
        while(j<bytes.length) {
            segment.bytes[segment.length++] = bytes.bytes[j];
            j += keysize;
        }

        CharCipher cipher = find_xor_char(segment, 0);
        out[i] = cipher.cipher;
    }

    return out;
}

void hex_dump(char *bytes, int len) {
    for(int i=0; i<len; i++) {
        printf("%02x ", bytes[i]);
    }
    printf("\n");
}

float hamming_distance_from_segments(ByteBuffer in, int keysize, int num) {
    float distance = 0;
    char segment_1[keysize+1];
    char segment_2[keysize+1];
    for(int i=0; i<num; i++) {
        memcpy(&segment_1[0], &in.bytes[keysize*i], keysize);
        segment_1[keysize] = '\0';

        memcpy(&segment_2[0], &in.bytes[keysize*i+keysize], keysize);
        segment_2[keysize] = '\0';

        distance += (float)hamming_distance(segment_1, keysize, segment_2, keysize)/keysize;
    }
    return distance / num;
}

int find_keysize(ByteBuffer bytes, int verbose) {
    const int MIN_KEYSIZE = 2;
    const int MAX_KEYSIZE = 40;

    assert(MAX_KEYSIZE*2 < bytes.length);

    struct match {
        int keysize;
        float distance;
    };
    struct match match = { -1, LONG_MAX };

    if(verbose)
        printf("Finding keysize\n");

    for(int i=MIN_KEYSIZE; i<=MAX_KEYSIZE; i++) {
        float distance = hamming_distance_from_segments(bytes, i, 10);
        if(verbose == 1)
            printf("  -> keysize: %i, distance: %f, best match: %f", i, distance, match.distance);
        if(distance < match.distance) {
            match.distance = distance;
            match.keysize = i;

            if(verbose == 1)
                printf("  -> New best match!");
        }
        if(verbose == 1)
            printf("\n");
    }

    return match.keysize;
}

long hamming_distance(char *a, size_t size_a, char *b, size_t size_b) {
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