#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void assert_equal(const char *expected, const char *actual) {
    if(strcasecmp(expected, actual) != false) {
        printf("Expected: '%s', got: '%s'\n", expected, actual);
        exit(1);
    }
    printf("Success! '%s'\n", actual);
}