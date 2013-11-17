#include "parser.h"
#include "server.h"
#include "dbg.h"
#include <ev.h>
#include <netinet/in.h>

#define UDP_BUF_LEN 2048

int server_count;
server *servers;

static void udp_callback(EV_P_ ev_io *w, int revents)
{
    char buffer[UDP_BUF_LEN];
    memset(buffer, 0, UDP_BUF_LEN);

    socklen_t slen = sizeof(struct sockaddr_in);
    struct sockaddr_in *input_addr = malloc(slen);

    int bytes_read = recvfrom(w->fd, buffer, UDP_BUF_LEN - 1, 0,
			      (struct sockaddr *) input_addr,
			      &slen);
    check (bytes_read >= 0, "Failed to read bytes");

    server *server = NULL;
    for (int idx = 0; idx < server_count; idx++) {
	if (servers[idx].socket_descriptor == w->fd) {
	    server = &servers[idx];
	}
    }
    check(server != NULL, "Server not found for fd: %d", w->fd);

    log_info("Server found: %d", server->port);
    syslog_parser *parser = syslog_parser_init();
    syslog_parser_execute(parser, buffer, bytes_read, 0);

    check_debug(!syslog_parser_has_error(parser), "Parser has error! %s", buffer);
    log_info("host name is %s", syslog_parser_hostname(parser));
    log_info("message is %s", syslog_parser_message(parser));
    log_info("Json message is %s", syslog_parser_json_output(parser));

 error:
    return;
}

int main ()
{
    server *server = server_init(1099);
    debug("Server port is: %d", server->port);
    int bind_result = server_bind(server);
    check(bind_result == 0, "Failed to bind: %d", bind_result);

    server_count = 1;
    servers = server;

    struct ev_loop *loop = EV_DEFAULT;
    ev_io udp_watcher;
    ev_io_init(&udp_watcher, udp_callback, server->socket_descriptor, EV_READ);
    ev_io_start(loop, &udp_watcher);
    ev_run(loop, 0);
    return 0;
 error:
    return -1;
}
