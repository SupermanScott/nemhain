#include "parser.h"
#include "server.h"
#include "dbg.h"
#include <ev.h>
#include "adt/hash.h"

#define UDP_BUF_LEN 2048

hash_t *servers;

int compare_fds (const void *fd_left, const void *fd_right);
uint32_t hash_fd (const void *fd);

int compare_fds (const void *fd_left, const void *fd_right)
{
    int left_value = *((int *) fd_left);
    int right_value = *((int *) fd_right);

    if (left_value == right_value){
	return 0;
    }
    if (left_value < right_value) {
	return -1;
    }
    return 1;
}

uint32_t hash_fd (const void *fd)
{
    uint32_t fd_value = *((uint32_t *) fd);
    return fd_value & HASH_VAL_T_MAX;
}

static void udp_callback(EV_P_ ev_io *w, int revents)
{
    log_info("Called");
    char buffer[UDP_BUF_LEN];
    memset(buffer, 0, UDP_BUF_LEN);

    int bytes_read = recv(w->fd, buffer, UDP_BUF_LEN - 1, 0);
    check (bytes_read >= 0, "Failed to read bytes");

    hnode_t *node = hash_lookup(servers, &w->fd);
    check (node != NULL, "Failed to get the server for: %d", w->fd);

    server *server = hnode_get(node);
    log_info("Server found: %d", server->port);
    syslog_parser *parser = syslog_parser_init();
    syslog_parser_execute(parser, buffer, bytes_read, 0);

    check_debug(!syslog_parser_has_error(parser), "Parser has error!");
    log_info("host name is %s", syslog_parser_hostname(parser));

 error:
    return;
}

int main ()
{
    servers = hash_create(10, (hash_comp_t) compare_fds,(hash_fun_t) hash_fd);
    server *server = server_init(1099);
    debug("Server port is: %d", server->port);
    int bind_result = server_bind(server);
    check(bind_result == 0, "Failed to bind: %d", bind_result);

    hash_alloc_insert(servers, &server->socket_descriptor, server);

    struct ev_loop *loop = EV_DEFAULT;
    ev_io udp_watcher;
    ev_io_init(&udp_watcher, udp_callback, server->socket_descriptor, EV_READ);
    ev_io_start(loop, &udp_watcher);
    ev_run(loop, 0);
    return 0;
 error:
    return -1;
}
