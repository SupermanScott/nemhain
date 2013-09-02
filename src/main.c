#include "parser.h"
#include "server.h"
#include "dbg.h"
#include <ev.h>

int main ()
{
    server *server = server_init(1099, syslog_parser_init());
    debug("Server port is: %d", server->port);
    struct ev_loop *loop = EV_DEFAULT;
    server_attach_to_event_loop(server, loop);
    return 0;
}
