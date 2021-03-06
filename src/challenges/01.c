#include <stdio.h>
#include <string.h>
#include "../crypto.h"
#include "../assert.h"

/*
Convert hex to base64

http://cryptopals.com/sets/1/challenges/1

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
    char input[] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

    ByteBuffer bytes = bytes_from_hex(&input[0]);
    printf("hex: %s\n", bytes.bytes);
    ByteBuffer encoded = base64_encode_bytes(bytes);

    bytes.length = 0;
    memset(bytes.bytes, 0, bytes.capacity);

    printf("encoded: ->%s<-\n", encoded.bytes);
    ByteBuffer decoded = base64_decode_bytes(encoded);
    printf("decoded: ->%s<-\n", decoded.bytes);

    assert_equal(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        encoded.bytes
        );

    free_bytes(&bytes);
    free_bytes(&encoded);
    free_bytes(&decoded);
}