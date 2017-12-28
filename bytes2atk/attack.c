#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

#include "includes.h"
#include "attack.h"

#define NATTACKS 11
#define NFLAGS 26

char attack_table[NATTACKS][10] = {
    "udp", "vse", "dns", "syn", "ack", "stomp", "greip", "greeth", "proxy", "udpplain", "http"
};

char flags_table[NFLAGS][10] = {
    "len", "rand", "tos", "ident", "ttl", "df", "sport", "dport", "domain", "dhid", "tcpcc", "urg", "ack", "psh", "rst", "syn", "fin", "seqnum", "acknum", "gcip", "method", "postdata", "path", "ssl", "conns", "source"
};

static void free_opts(struct attack_option *opts, int len)
{
    int i;

    if (opts == NULL)
        return;

    for (i = 0; i < len; i++)
    {
        if (opts[i].val != NULL)
            free(opts[i].val);
    }
    free(opts);
}

void attack_parse(char *buf, int len, char *plain, char *err)
{
    int i;
    uint32_t duration;
    ATTACK_VECTOR vector;
    uint8_t targs_len, opts_len;
    struct attack_target *targs = NULL;
    struct attack_option *opts = NULL;

    // Read in attack duration uint32_t
    if (len < sizeof (uint32_t)) {
        strcpy(err, "Buflen too small.");
        goto cleanup;
    }

    duration = ntohl(*((uint32_t *)buf));
    buf += sizeof (uint32_t);
    len -= sizeof (uint32_t);

    // Read in attack ID uint8_t
    if (len == 0) {
        strcpy(err, "Missing attack ID.");
        goto cleanup;
    }
    vector = (ATTACK_VECTOR)*buf++;
    len -= sizeof (uint8_t);

    // Read in target count uint8_t
    if (len == 0) {
        strcpy(err, "Missing target count.");
        goto cleanup;
    }
    targs_len = (uint8_t)*buf++;
    len -= sizeof (uint8_t);
    if (targs_len == 0) {
        strcpy(err, "Target args can't be zero.");
        goto cleanup;
    }

    // Read in all targs
    if (len < ((sizeof (ipv4_t) + sizeof (uint8_t)) * targs_len)) {
        strcpy(err, "Missing target args.");
        goto cleanup;
    }

    targs = calloc(targs_len, sizeof (struct attack_target));
    for (i = 0; i < targs_len; i++)
    {
        targs[i].addr = *((ipv4_t *)buf);
        buf += sizeof (ipv4_t);
        targs[i].netmask = (uint8_t)*buf++;
        len -= (sizeof (ipv4_t) + sizeof (uint8_t));

        targs[i].sock_addr.sin_family = AF_INET;
        targs[i].sock_addr.sin_addr.s_addr = targs[i].addr;
    }

    // Read in flag count uint8_t
    if (len < sizeof (uint8_t)) {
        strcpy(err, "Missing flag count.");
        goto cleanup;
    }
    opts_len = (uint8_t)*buf++;
    len -= sizeof (uint8_t);

    // Read in all opts
    if (opts_len > 0)
    {
        opts = calloc(opts_len, sizeof (struct attack_option));
        for (i = 0; i < opts_len; i++)
        {
            uint8_t val_len;

            // Read in key uint8
            if (len < sizeof (uint8_t)) {
                strcpy(err, "Missing flag key.");
                goto cleanup;
            }
            opts[i].key = (uint8_t)*buf++;
            len -= sizeof (uint8_t);

            // Read in data length uint8
            if (len < sizeof (uint8_t)) {
                strcpy(err, "Missing flag len.");
                goto cleanup;
            }
            val_len = (uint8_t)*buf++;
            len -= sizeof (uint8_t);

            if (len < val_len) {
                strcpy(err, "Missing flag data.");
                goto cleanup;
            }
            opts[i].val = calloc(val_len + 1, sizeof (char));
            util_memcpy(opts[i].val, buf, val_len);
            buf += val_len;
            len -= val_len;
        }
    }

    errno = 0;

    // Store parse result instead of starting attack
    if (vector >= NATTACKS) {
        strcpy(err, "Unknown attack specified.");
        goto cleanup;
    }
    char *vector_name = attack_table[vector];
    char targets[5100] = "";
    char options[5100] = "";
    char options_buf[1024];
    char prefix_buf[20];
    uint32_t prefix;
    uint8_t netmask;
    uint8_t key;

    for (int i = 0; i < targs_len; i++) {
        prefix = targs[i].addr;
        netmask = targs[i].netmask;

        sprintf(prefix_buf, "%d.%d.%d.%d/%d%c",
                prefix & 255, (prefix >> 8) & 255,
                (prefix >> 16) & 255, prefix >> 24,
                netmask, i < targs_len-1 ? ',' : '\0');
        strcat(targets, prefix_buf);
    }

    for (int i = 0; i < opts_len; i++) {
        if (opts[i].key < NFLAGS) {
            sprintf(options_buf, "%s=%s%c", flags_table[opts[i].key], opts[i].val, i < opts_len-1 ? ' ' : '\0');
            strcat(options, options_buf);
        }
    }

    sprintf(plain, "%s %s %d %s",
            vector_name, targets, duration, options);
    // attack_start(duration, vector, targs_len, targs, opts_len, opts);

    // Cleanup
    cleanup:
    if (targs != NULL)
        free(targs);
    if (opts != NULL)
        free_opts(opts, opts_len);
}
