#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "http.h"

static const char *good[] = {
    "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
        "Host: localhost\r\n"
        "Accept: */*\r\n"
        "\r\n",
    "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
        "HOST:\t     localhost\r\n"
        "Accept: */*\r\n"
        "\r\n",
    "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
        "HOST:\t     localhost:8080\r\n"
        "Accept: */*\r\n"
        "\r\n",
    "GET / HTTP/1.1\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\n"
        "Host: localhost\n"
        "Accept: */*\n"
        "\n"
};
static const char *bad[] = {
    "GET / HTTP/1.0\r\n"
        "\r\n",
    "",
    "G",
    "GET ",
    "GET / HTTP/1.0\n"
        "\n",
    "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
        "Hostname: localhost\r\n"
        "Accept: */*\r\n"
        "\r\n",
    "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
        "Accept: */*\r\n"
        "\r\n",
};
static const char *incomplete[] = {
    "GET / HTTP/1.1\r\n"
        "Host: exam",
    "GET / HTTP/1.1\r\n"
        "Host: example.com\r",
    "GET / HTTP/1.1\n"
        "Host: example.com",
    "GET / HTTP/1.1\r\n"
        "Accept: */*\r\n"
        "\r",
};

int main(void) {
    unsigned int i;
    int result;
    char *hostname;

    for (i = 0; i < sizeof(good) / sizeof(const char *); i++) {
        hostname = NULL;

        result = http_protocol->parse_packet(good[i], strlen(good[i]), &hostname);

        assert(result == 9);

        assert(NULL != hostname);

        assert(0 == strcmp("localhost", hostname));

        free(hostname);
    }

    for (i = 0; i < sizeof(bad) / sizeof(const char *); i++) {
        hostname = NULL;

        result = http_protocol->parse_packet(bad[i], strlen(bad[i]), &hostname);

        assert(result < 0);

        assert(hostname == NULL);
    }

    /* Requests may arrive in pieces: every prefix of a good request must
     * either be incomplete or yield the complete hostname, never a hostname
     * cut short (e.g. "loc" from "Host: loc") */
    for (i = 0; i < sizeof(good) / sizeof(const char *); i++) {
        for (size_t len = 0; len < strlen(good[i]); len++) {
            hostname = NULL;

            result = http_protocol->parse_packet(good[i], len, &hostname);

            if (result == -1) {
                assert(hostname == NULL);
            } else {
                assert(result == 9);
                assert(hostname != NULL);
                assert(0 == strcmp("localhost", hostname));
                free(hostname);
            }
        }
    }

    /* A line is only complete once its <LF> has arrived: a request cut off
     * inside the Host header (or the blank line) is incomplete, it must not
     * be routed on "exam" or reported as having no Host header */
    for (i = 0; i < sizeof(incomplete) / sizeof(const char *); i++) {
        hostname = NULL;

        result = http_protocol->parse_packet(incomplete[i], strlen(incomplete[i]), &hostname);

        assert(result == -1);

        assert(hostname == NULL);
    }

    /* Once the Host line is complete the full hostname is available, without
     * waiting for the rest of the headers */
    {
        static const char complete_host[] = "GET / HTTP/1.1\r\nHost: example.com\r\n";

        hostname = NULL;

        result = http_protocol->parse_packet(complete_host, sizeof(complete_host) - 1, &hostname);

        assert(result == 11);

        assert(NULL != hostname);

        assert(0 == strcmp("example.com", hostname));

        free(hostname);
    }

    return 0;
}

