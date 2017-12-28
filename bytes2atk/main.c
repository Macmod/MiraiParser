#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include "attack.h"
#define DEBUG 0
#define BUFSIZE 8192

int main() {
    char *full_cmd = calloc(sizeof(char), BUFSIZE);
    char *plain = calloc(sizeof(char), BUFSIZE);
    char *err = calloc(sizeof(char), BUFSIZE);
    char *tmp;
    uint16_t len;
    size_t n;

    tmp = full_cmd;
    while ((n = fread(tmp, sizeof(char), BUFSIZE, stdin)) != 0) {
        tmp += n;
    }

    tmp = full_cmd;
    len = *(uint16_t*)tmp;
    len = ntohs(len);
    tmp += sizeof(len);

    attack_parse(tmp, len, plain, err);
    if (*plain != '\0') {
        printf("%s\n", plain);
    } else {
#if DEBUG
        printf("ERR|%s\n", err);
#endif
    }

    free(full_cmd);
    free(plain);
    free(err);

    return 0;
}
