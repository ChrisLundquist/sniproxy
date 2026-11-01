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
/* Requests cut off before the Host line is terminated, as can happen when
 * it is split across TCP segments: these must not yield a (truncated)
 * hostname, but report an incomplete request so we wait for more data */
static const char *incomplete[] = {
    "GET / HTTP/1.1\r\n"
        "Host",
    "GET / HTTP/1.1\r\n"
        "Host:",
    "GET / HTTP/1.1\r\n"
        "Host: ",
    "GET / HTTP/1.1\r\n"
        "Host: l",
    "GET / HTTP/1.1\r\n"
        "Host: local",
    "GET / HTTP/1.1\r\n"
        "Host: localhos",
    "GET / HTTP/1.1\r\n"
        "Host: localhost",
    "GET / HTTP/1.1\r\n"
        "Host: localhost\r",
    "GET / HTTP/1.1\r\n"
        "Host: localhost:",
    "GET / HTTP/1.1\r\n"
        "Host: localhost:80",
    "GET / HTTP/1.1\n"
        "Host: localhost",
    "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0\r\n"
        "Host: localhost",
    /* blank line ending the headers is not terminated either */
    "GET / HTTP/1.1\r\n"
        "Accept: */*\r\n"
        "\r",
};

/*
 * Feed every prefix of a complete request to the parser: until the Host
 * line's terminating <LF> has arrived the request must be incomplete, after
 * that it must yield the full hostname.
 */
static void
test_prefixes(const char *request) {
    size_t request_len = strlen(request);
    const char *host = strstr(request, "localhost");
    assert(host != NULL);
    const char *host_eol = strchr(host, '\n');
    assert(host_eol != NULL);
    size_t complete_len = (size_t)(host_eol - request) + 1;

    for (size_t len = 0; len <= request_len; len++) {
        /* exact sized copy, so reading past len is caught by ASan/valgrind */
        char *buf = malloc(len > 0 ? len : 1);
        assert(buf != NULL);
        memcpy(buf, request, len);

        char *hostname = NULL;
        int result = http_protocol->parse_packet(buf, len, &hostname);

        if (len < complete_len) {
            assert(result == -1);
            assert(hostname == NULL);
        } else {
            assert(result == 9);
            assert(NULL != hostname);
            assert(0 == strcmp("localhost", hostname));
        }

        free(hostname);
        free(buf);
    }
}

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

    for (i = 0; i < sizeof(incomplete) / sizeof(const char *); i++) {
        hostname = NULL;

        result = http_protocol->parse_packet(incomplete[i], strlen(incomplete[i]), &hostname);

        assert(result == -1);

        assert(hostname == NULL);
    }

    for (i = 0; i < sizeof(good) / sizeof(const char *); i++)
        test_prefixes(good[i]);

    return 0;
}

