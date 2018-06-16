#include <stdio.h>
#include <string.h>
#include "crypto.h"

/*
Convert hex to base64

The string:
49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

Should produce:
SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

So go ahead and make that happen. You'll need to use this code for the rest of 
the exercises.

Cryptopals Rule
Always operate on raw bytes, never on encoded strings. Only use hex and base64 
for pretty-printing.
*/
int main(int argc, char **argv) {
    if(argc != 2) {
        printf("Usage: challenge_01 {hex}\n");
        return 1;
    }

    struct Bytes_t bytes = create_bytes(1024);
    set_bytes_from_hex(argv[1], &bytes);

    for(int i=0; i<bytes.length; i++) {
        printf("%02X ", bytes.bytes[i]);
    }

    free(bytes.bytes);

    printf("\n%s\n", argv[1]);
}