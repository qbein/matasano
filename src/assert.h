#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Text Reset
#define Color_Off "\033[0m"

// Regular Colors
#define Black "\033[0;30m"
#define Red "\033[0;31m"
#define Green "\033[0;32m"
#define Yellow "\033[0;33m"
#define Blue "\033[0;34m"
#define Purple "\033[0;35m"
#define Cyan "\033[0;36m"
#define White "\033[0;37m"

void assert_equal(const char *expected, const char *actual) {
    if(strcasecmp(expected, actual) != false) {
        printf(
            "%sExpected: '%s', got: '%s'%s\n",
            Red, expected, actual, Color_Off
        );
        exit(1);
    }
    printf("%sSuccess!%s '%s'\n", Green, Color_Off, actual);
}