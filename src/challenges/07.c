#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "../crypto.h"
#include "../assert.h"

void handleErrors() {
    fwrite(Red, sizeof(char), strlen(Red), stderr);
    //printf("%s", Red);
    ERR_print_errors_fp(stderr);
    fwrite(Color_Off, sizeof(char), strlen(Color_Off), stderr);
    exit(1);
}

/*
AES in ECB mode

The Base64-encoded content in this file has been encrypted via AES-128 in ECB
mode under the key "YELLOW SUBMARINE". (case-sensitive, without the quotes;
exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes
long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

Do this with code.
You can obviously decrypt this using the OpenSSL command-line tool, but we're
having you get ECB working in code for a reason. You'll need it a lot later on,
and not just for attacking ECB.
*/
int main(int argc, char **argv)
{
    EVP_CIPHER_CTX *ctx;

    ByteBuffer encoded = base64_decode_bytes(bytes_from_file("assets/7.txt"));
    ByteBuffer key = bytes_from_str("YELLOW SUBMARINE");
    ByteBuffer out = create_bytes(1024);

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    unsigned char iv[16] = {0};

    if (1 != EVP_DecryptInit_ex(
        ctx, EVP_aes_128_ecb(), NULL, (unsigned char*)key.bytes, &iv[0]))
        handleErrors();

    if (1 != EVP_DecryptUpdate(
        ctx,
        (unsigned char*)out.bytes,
        (int *)&out.length,
        (unsigned char*)encoded.bytes,
        encoded.length))
    {
        handleErrors();
    }

    int len = 0;
    if (1 != EVP_DecryptFinal_ex(
        ctx,
        (unsigned char*)out.bytes + out.length,
        &len))
    {
        handleErrors();
    }

    EVP_CIPHER_CTX_free(ctx);

    out.length += len;
    out.bytes[out.length] = 0;

    //hex_dump((unsigned char*)out.bytes, out.length);

    out.bytes[0x20] = 0;

    assert_equal(
        "I'm back and I'm ringin' the bel",
        out.bytes);

    return 0;
}
