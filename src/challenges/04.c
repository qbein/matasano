#include <stdio.h>
#include <string.h>
#include "../crypto.h"
#include "../assert.h"

/*
Detect single-character XOR

One of the 60-character strings in assets/4.txt file has been encrypted by
single-character XOR.

Find it.
(Your code from #3 should help.)
*/
int main(int argc, char **argv) {
    FILE *fp = fopen("assets/4.txt", "r");

    size_t len;
    char *line;

    Char_cipher_t highscore = { 0, 0 };
    Char_cipher_t linescore = { 0, 0 };

    Bytes_t highscore_bytes = create_bytes(1024);
    Bytes_t line_bytes = create_bytes(1024);

    while(((line = fgetln(fp, &len))) != NULL) {
        if(line[len-1]==0x0a) line[len-1] = 0;
        else line[len] = 0;

        bytes_from_hex(line, &line_bytes);
        linescore = find_xor_char(&line_bytes);

        if(linescore.score > highscore.score) {
            copy_bytes(&line_bytes, &highscore_bytes);

            highscore.cipher = linescore.cipher;
            highscore.score = linescore.score;
        }
    }

    fclose(fp);

    printf("Found cipher: %c (score: %f)\n", highscore.cipher, highscore.score);

    Bytes_t output = create_bytes(1024);
    xor_char(&highscore_bytes, highscore.cipher, &output);

    assert_equal(
        "Now that the party is jumping\n",
        output.bytes
    );

    free_bytes(&output);

    free_bytes(&line_bytes);
    free_bytes(&highscore_bytes);
}