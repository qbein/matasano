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
    char data_hex[] =
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    ByteBuffer data = create_bytes(1024);
    bytes_from_hex(&data_hex[0], &data);

    CharCipher cipher = find_xor_char(&data);

    xor_char(&data, cipher.cipher);

    assert_equal(
        data.bytes,
        "Cooking MC's like a pound of bacon"
        );

    free_bytes(&data);
}