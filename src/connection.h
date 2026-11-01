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
#ifndef CONNECTION_H
#define CONNECTION_H

#include <sys/socket.h>
#include <sys/queue.h>
#include <ev.h>
#include "listener.h"
#include "buffer.h"

struct Connection {
    enum State {
        NEW,            /* Before successful accept */
        ACCEPTED,       /* Newly accepted client connection */
        PARSED,         /* Parsed initial request and extracted hostname */
        RESOLVING,      /* DNS query in progress */
        RESOLVED,       /* Server socket address resolved */
        CONNECTED,      /* Connected to server, either side may be half-closed */
        SERVER_CLOSED,  /* Server socket closed, flushing to client */
        CLIENT_CLOSED,  /* Client socket closed, flushing to server */
        CLOSED          /* Both sockets closed */
    } state;

    struct {
        struct sockaddr_storage addr, local_addr;
        socklen_t addr_len, local_addr_len;
        struct ev_io watcher;
        struct Buffer *buffer;
        int eof;        /* Peer shut down its sending side: no more input */
        int shut_wr;    /* We called shutdown(SHUT_WR) toward this peer */
    } client, server;
    struct Listener *listener;
    const char *hostname; /* Requested hostname */
    size_t hostname_len;
    size_t header_len;
    struct ResolvQuery *query_handle;
    ev_tstamp established_timestamp; /* wall clock (ev_now()), for reporting */
    /* monotonic_time() when the connection was accepted, and when we started
     * connecting to the server: timeouts are measured on this clock so that
     * stepping the wall clock doesn't trigger or suspend them */
    ev_tstamp accepted_monotonic;
    ev_tstamp connect_monotonic;
    int use_proxy_header;

    TAILQ_ENTRY(Connection) entries;
};

void init_connections(void);
int accept_connection(struct Listener *, struct ev_loop *);
void free_connections(struct ev_loop *);
void print_connections(void);

#endif
