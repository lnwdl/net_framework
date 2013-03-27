#ifndef __CONNECTION_H__
#define __CONNECTION_H__

#include <stdio.h>
#include <common_ssl.h>


/* connections cache */
struct connections_head_s;
typedef struct connections_head_s connections_head_t;

/* connection struct */
struct connections_s;
typedef struct connection_s connection_t;

struct connections_head_s {
    SSL_CTX *ctx; /* SSL configuration for all the connection cache */
    connection_t *connections;
    connection_t *free_connections;
    size_t connections_n;
    size_t free_connections_n;
    int epfd; /* epoll file descriptor for all the connection cache */
};

struct connection_s {
    int fd;
    SSL *ssl;
    struct connection_s *next;
    void (*handler)(connections_head_t *head, connection_t *conn);
    unsigned char accept: 1;
    unsigned char write: 1;
};

void
destroy_connections(connections_head_t *head);

connections_head_t *
init_connections(size_t size);

connection_t *
get_connection(connections_head_t *head);

void 
free_connection(connections_head_t *head, connection_t *conn);

#endif
