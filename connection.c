#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <common_ssl.h>
#include <connection.h>

connection_t *
get_connection(connections_head_t *head)
{
    connection_t *conn;

    conn = head->free_connections;
    if (NULL == conn) {
        goto error;
    }

    head->free_connections = conn->next;
    head->free_connections_n--;

    bzero(conn, sizeof(connection_t));

    return conn;
error:
    return NULL;
}

void 
free_connection(connections_head_t *head, connection_t *conn)
{
    if (conn->ssl) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
    }

    if (conn->fd) close(conn->fd);

    conn->next = head->free_connections;
    head->free_connections++;
}

void
destroy_connections(connections_head_t *head)
{
    size_t i;

    if (head) {
        if (head->ctx) SSL_CTX_free(head->ctx);
        if (head->epfd) close(head->epfd);
        if (head->connections) {
            for (i = 0; i < head->connections_n; ++i) {
                free_connection(head, head->connections + i);
            }

            free(head->connections);
        }
    }
}

connections_head_t *
init_connections(size_t size)
{
    connections_head_t *head;
    connection_t *next;
    size_t i;

    head = malloc(sizeof(connections_head_t));
    if (NULL == head) {
        goto error;
    }
    bzero(head, sizeof(connections_head_t));

    head->connections_n = size;
    head->connections = calloc(size, sizeof(connection_t));
    if (NULL == head->connections) {
        goto error;
    }

    i = size;
    next = NULL;
    do {
        i--;
        head->connections[i].next = next;
        next = &head->connections[i];
    } while(i);

    head->free_connections = head->connections;
    head->free_connections_n = size;

    return head;
error:
    destroy_connections(head);
    return NULL;
}

