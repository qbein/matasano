#include <stdio.h>
#include <string.h>
#include "crypto.h"
#include "assert.h"

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
    char input[] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

    struct Bytes_t bytes = create_bytes(1024);
    set_bytes_from_hex(&input[0], &bytes);

    char encoded[1024];
    memset(&encoded[0], 0, 1024);
    base64_encode(&bytes, &encoded[0]);

    assert_equal(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        encoded
        );

    free(bytes.bytes);
}