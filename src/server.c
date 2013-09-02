/**
 *
 * Copyright (c) 2013, Scott Reynolds.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 *     * Neither the name of the Nemhain Project, Scott Reynolds, the names
 *       of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "server.h"
#include <ev.h>
#include "dbg.h"
#include <netinet/in.h>

static void server_udp_callback(EV_P_ ev_io *w, int revents);

server *server_init(int port, syslog_parser *p)
{
    server *s = malloc(sizeof(server));
    *s = (server) {
	.port = port,
	.parser = p,
	.socket_descriptor = 0
    };
    return s;
}

void server_attach_to_event_loop(server *server, struct ev_loop *loop)
{
    log_info("Starting UDP server on port: %d", server->port);

    // Setup a udp listening socket.
    server->socket_descriptor = socket(PF_INET, SOCK_DGRAM, 0);
    check(server->socket_descriptor >= 0, "Failed to create socket");

    server->address = malloc(sizeof(*server->address));
    server->address->sin_family = AF_INET;
    server->address->sin_port = htons(server->port);
    server->address->sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(server->socket_descriptor,
	     server->address,
	     sizeof(*server->address)) != 0) {
        log_err("Failed to bind: %d", sizeof(*server->address));
    }

    ev_io udp_watcher;
    ev_io_init(&udp_watcher, server_udp_callback, server->socket_descriptor, EV_READ);
    ev_io_start(loop, &udp_watcher);

    return;

 error:
    // @TODO: server->address probably needs to be destroyed.
    return;
}

static void server_udp_callback(EV_P_ ev_io *w, int revents)
{
    log_info("something has awaken!");
}
