#include <stdio.h>
#include <string.h>
#include "../crypto.h"
#include "../assert.h"

/*
Fixed XOR

http://cryptopals.com/sets/1/challenges/2

Write a function that takes two equal-length buffers and produces their XOR
combination.

If your function works properly, then when you feed it the string:
1c0111001f010100061a024b53535009181c

... after hex decoding, and when XOR'd against:
686974207468652062756c6c277320657965

... should produce:
746865206b696420646f6e277420706c6179
*/
int main(int argc, char **argv) {
    char input_hex[] = "1c0111001f010100061a024b53535009181c";
    char xor_hex[] = "686974207468652062756c6c277320657965";

    struct Bytes_t input = create_bytes(1024);
    bytes_from_hex(&input_hex[0], &input);

    struct Bytes_t xor = create_bytes(1024);
    bytes_from_hex(&xor_hex[0], &xor);

    struct Bytes_t output = create_bytes(1024);
    xor_bytes(&input, &xor, &output);

    char output_hex[1024];
    memset(output_hex, 0, 1024);
    hex_from_bytes(&output, &output_hex[0]);

    assert_equal(
        "746865206b696420646f6e277420706c6179",
        output_hex
        );

    free_bytes(&input);
    free_bytes(&xor);
}