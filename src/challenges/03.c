#include <stdio.h>
#include <string.h>
#include "../crypto.h"
#include "../assert.h"

/*
Single-byte XOR cipher

The hex encoded string:
1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

... has been XOR'd against a single character. Find the key, decrypt the
message. You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character
frequency is a good metric. Evaluate each output and choose the one with the
best score.

Achievement Unlocked
You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.
*/
int main(int argc, char **argv) {
    char input_hex[] =
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    struct Bytes_t input = create_bytes(1024);
    bytes_from_hex(&input_hex[0], &input);
    Char_cipher_t cipher = find_xor_char(&input);
    struct Bytes_t xor = create_bytes(1024);
    bytes_from_char(cipher.cipher, &xor);

    struct Bytes_t output = create_bytes(1024);

    xor_bytes(&input, &xor, &output);

    assert_equal(
        output.bytes,
        "Cooking MC's like a pound of bacon"
        );

    free_bytes(&input);
}