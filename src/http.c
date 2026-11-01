/*
 * Copyright (c) 2011 and 2012, Dustin Lundquist <dustin@null-ptr.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h> /* malloc() */
#include <string.h> /* strncpy() */
#include <strings.h> /* strncasecmp() */
#include <ctype.h> /* isblank(), isdigit() */
#include <sys/types.h> /* ssize_t */
#include "http.h"
#include "protocol.h"

#define SERVER_NAME_LEN 256


static int parse_http_header(const char *, size_t, char **);
static int get_header(const char *, const char *, size_t, char **);
static ssize_t next_header(const char **, size_t *);


static const char http_503[] =
    "HTTP/1.1 503 Service Temporarily Unavailable\r\n"
    "Content-Type: text/html\r\n"
    "Connection: close\r\n\r\n"
    "Backend not available";

const struct Protocol *const http_protocol = &(struct Protocol){
    .name = "http",
    .default_port = 80,
    .parse_packet = &parse_http_header,
    .abort_message = http_503,
    .abort_message_len = sizeof(http_503) - 1,
};

/*
 * Parses a HTTP request for the Host: header
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  -1   - Incomplete request
 *  -2   - No Host header included in this request
 *  -3   - Invalid hostname pointer
 *  -4   - malloc failure
 *  < -4 - Invalid HTTP request
 *
 */
static int
parse_http_header(const char* data, size_t data_len, char **hostname) {
    int result, i;

    if (hostname == NULL)
        return -3;

    result = get_header("Host:", data, data_len, hostname);
    if (result < 0)
        return result;

    /*
     *  if the user specifies the port in the request, it is included here.
     *  Host: example.com:80
     *  Host: [2001:db8::1]:8080
     *  so we trim off port portion
     */
    for (i = result - 1; i >= 0; i--)
        if ((*hostname)[i] == ':') {
            (*hostname)[i] = '\0';
            result = i;
            break;
        } else if (!isdigit((*hostname)[i])) {
            break;
        }

    return result;
}

static int
get_header(const char *header, const char *data, size_t data_len, char **value) {
    ssize_t result;
    size_t len, header_len;

    header_len = strlen(header);

    /* loop through headers stopping at first blank line */
    while ((result = next_header(&data, &data_len)) > 0) {
        len = (size_t)result;
        if (len > header_len && strncasecmp(header, data, header_len) == 0) {
            /* Eat leading whitespace */
            while (header_len < len && isblank(data[header_len]))
                header_len++;

            *value = malloc(len - header_len + 1);
            if (*value == NULL)
                return -4;

            strncpy(*value, data + header_len, len - header_len);
            (*value)[len - header_len] = '\0';

            return len - header_len;
        }
    }

    /* We ran out of data before reaching the blank line that ends the
     * headers, so we do not have a complete HTTP request yet */
    if (result < 0)
        return -1;

    return -2;
}

/*
 * Advances *data past the current line (the request line on the first call,
 * the previously returned header after that) and finds the next line.
 *
 * Lines end with <LF>, optionally preceded by <CR>. A line that runs to the
 * end of the buffer may have been cut short by a TCP segment boundary, so it
 * is never returned as a header.
 *
 * Returns:
 *  >0  - length of the next header line, excluding its line terminator
 *   0  - the next line is the blank line ending the headers
 *  -1  - the current or next line is not terminated; incomplete request
 */
static ssize_t
next_header(const char **data, size_t *len) {
    const char *eol;
    size_t header_len;

    /* Skip past the <LF> ending the current line */
    eol = memchr(*data, '\n', *len);
    if (eol == NULL)
        return -1;

    *len -= (size_t)(eol - *data) + 1;
    *data = eol + 1;

    /* Find the <LF> ending the next line */
    eol = memchr(*data, '\n', *len);
    if (eol == NULL)
        return -1;

    header_len = (size_t)(eol - *data);
    /* ignore preceding <CR> */
    if (header_len > 0 && (*data)[header_len - 1] == '\r')
        header_len--;

    return (ssize_t)header_len;
}
