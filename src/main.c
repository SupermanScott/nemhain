#include "parser.h"
#include "server.h"
#include "dbg.h"
#include <ev.h>

static void udp_callback(EV_P_ ev_io *w, int revents)
{
    log_info("Called");
}

int main ()
{
    server *server = server_init(1099, syslog_parser_init());
    debug("Server port is: %d", server->port);
    int bind_result = server_bind(server);
    check(bind_result == 0, "Failed to bind: %d", bind_result);

    struct ev_loop *loop = EV_DEFAULT;
    ev_io udp_watcher;
    ev_io_init(&udp_watcher, udp_callback, server->socket_descriptor, EV_READ);
    ev_io_start(loop, &udp_watcher);
    ev_run(loop, 0);
    return 0;
 error:
    return -1;
}
