#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <openssl/ssl.h>

#include <public.h>
#include <common_net.h>
#include <common_ssl.h>
#include <connection.h>

static void
ssl_rdwr_handler(connections_head_t *head, connection_t *conn)
{
    /* We have data on the fd waiting to be read. Read and
     * display it. We must read what ever data is availabe
     * completely, as we are running in edge-triggered mode
     * and won't get a notification again for the same data
     */
    int done = 0;
    ssize_t count, wrlen;
    char buf[512];
    SSL_SESSION *sess;

    sess = SSL_get_session(conn->ssl);
    printf("The session is %p\n", sess);

    while (1) {
        count = SSL_read(conn->ssl, buf, sizeof buf);
        if (-1 == count) {
            /* If errno == EAGAIN, that means we have read all
             * data. So go back to the main loop.
             */
            if (errno != EAGAIN) {
                ERROR_MSG("SSL_read\n");
                done = 1;
            }
            break;
        } else if (0 == count) {
            /* End of file. The remote has closed the 
             * connection
             */
            done = 1;
            printf("%s|%d|remote close socket\n", __FILE__, __LINE__);
            break;
        }

        wrlen = SSL_write(conn->ssl, buf, count);
        if (wrlen <= 0) {
            if (errno != EAGAIN) {
                ERROR_MSG("SSL_write");
                done = 1;
            }
        } else { /* write ok, wait for the next read */
            break;
        }
    }

    if (done) {
        printf("Closed connection on descriptor %d\n",
            conn->fd);

        /* Closing the descriptor wil make epoll remove it
         * from the set of descriptors which are monitored.
         */
        free_connection(head, conn);
    }
}

static void
do_ssl_accept(connections_head_t *head, connection_t *conn)
{
    long err;
    int ret, ssl_err;

    if (conn->accept == 0) { /* first invoke do_ssl_accept */
        conn->ssl = SSL_new(head->ctx);
        if (NULL == conn->ssl) {
            perror("SSL_new");
            goto error;
        }

        if (SSL_set_fd(conn->ssl, conn->fd) != 1) {
            perror("SSL_set_fd");
            goto error;
        }    

        conn->accept = 1;
    }

    ret = SSL_accept(conn->ssl);
    if (ret != 1) {
        ssl_err = SSL_get_error(conn->ssl, ret);
        if (ssl_err != SSL_ERROR_WANT_READ
                && ssl_err != SSL_ERROR_WANT_WRITE) {
            ERROR_MSG("ssl_err is: %d\n", ssl_err);
            ERROR_MSG("ssl_accept");
            goto error;
        }

        /* called next epoll_wait loop */
        return;
    }

    err = post_connection_check(conn->ssl, "192.168.1.10");
    if (err != X509_V_OK) {
        ERROR_MSG("post_connection_check error\n");
        ERROR_MSG("-Error: peer certificate: %s\n", 
                X509_verify_cert_error_string(err));
    }

    conn->handler = ssl_rdwr_handler;
error:
    return;
}

static void
accept_handler(connections_head_t *head, connection_t *conn)
{
    struct sockaddr in_addr;
    socklen_t in_len;
    int infd, lsfd;
    int ret;
    connection_t *new_conn;
    struct epoll_event event;
    char hbuf[64], sbuf[64];

    /* We have a notification on the listening socket, which
     * means one or more incoming connections.
     */
    while (1)
    {
        in_len = sizeof(struct sockaddr);
        lsfd = conn->fd;

        infd = accept(lsfd, &in_addr, &in_len);
        if (-1 == infd) {
            if ((EAGAIN == errno)
                || (EWOULDBLOCK == errno)) {
                /* We have processed all incoming
                 * connections.
                 */
                break;
            } else {
                ERROR_MSG("accept");
                break;
            }
        }

        ret = getnameinfo(&in_addr, in_len,
                hbuf, sizeof hbuf,
                sbuf, sizeof sbuf,
                NI_NUMERICHOST | NI_NUMERICSERV);
        if (0 == ret) {
            printf("Accepted connection on descriptor %d "
                            "(host=%s, port=%s)\n", infd, hbuf, sbuf);
        }

        /* Make the incoming socket non-blocking and add it
         * to the list of fds to monitor
         */
        ret = make_socket_non_blocking(infd);
        if (-1 == ret) {
            ERROR_MSG("make_socket_non_blocking\n");
            abort();
        }

        new_conn = get_connection(head);
        if (NULL == new_conn) {
            ERROR_MSG("get_connection\n");
            abort();
        }

        new_conn->fd = infd;
        new_conn->ssl = NULL;
        //new_conn->handler = rdwr_handler;
        new_conn->handler = do_ssl_accept;

        event.data.ptr = new_conn;
        event.events = EPOLLIN | EPOLLET;
        ret = epoll_ctl(head->epfd, EPOLL_CTL_ADD, infd, &event);
        if (-1 == ret) {
            ERROR_MSG("epoll_ctl\n");
            abort();
        }
    }
}

int main(int argc, char *argv[])
{
    int lsfd;
    int ret, n, i;
    struct epoll_event event;
    struct epoll_event *events = NULL;
    connection_t *conn;
    connections_head_t *head = NULL;

    if (argc != 2) {
        fprintf(stdout, "Usage: %s [port]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* init connections cache */
    head = init_connections(MAX_CONNECTIONS);
    if (NULL == head) {
        ERROR_MSG("init_connections\n");
        goto error;
    }

    /* init SSL data */
    ret = init_OpenSSL();
    if (ret != 0) {
        ERROR_MSG("init_OpenSSL\n");
        goto error;
    }

    head->ctx = init_ssl_ctx(SRV_CERTFILE, SRV_PRIKEY, SRV_CAFILE);
    if (NULL == head->ctx) {
        ERROR_MSG("init_ssl_ctx error\n");
        goto error;
    }

    /* init epoll's data */
    head->epfd = epoll_create(MAX_CONNECTIONS);
    if (-1 == head->epfd) {
        ERROR_MSG("epoll_create\n");
        goto error;
    }

    events = calloc(MAX_EVENTS, sizeof(struct epoll_event));
    if (NULL == events) {
        ERROR_MSG("calloc\n");
        goto error;
    }

    /* listen's data */
    lsfd = start_listen(argv[1]);
    if (lsfd < 0) {
        ERROR_MSG("start_listen\n");
        goto error;
    }

    /* add the lsfd to events */
    conn = get_connection(head);
    if (NULL == conn) {
        ERROR_MSG("get_connection\n");
        goto error;
    }

    conn->fd = lsfd;
    conn->handler = accept_handler;

    event.data.ptr = conn;
    event.events = EPOLLIN | EPOLLET;
    ret = epoll_ctl(head->epfd, EPOLL_CTL_ADD, lsfd, &event);
    if (-1 == ret) {
        ERROR_MSG("epoll_ctl\n");
        goto error;
    }

    /* The event loop */
    while (1)
    {
        n = epoll_wait(head->epfd, events, MAX_EVENTS, -1);
        for (i = 0; i < n; ++i)
        {
            conn = events[i].data.ptr;

            if ((events[i].events & EPOLLERR)
                || (events[i].events & EPOLLHUP)
                || !(events[i].events & EPOLLIN))
            {
                /* it will delete the event from events at the same time 
                 * due to invoked close
                 */
                free_connection(head, conn);
            } else {
                if (conn->handler) {
                    conn->handler(head, conn);
                }
            }
        }
    }

error:
    if (events) free(events);
    destroy_connections(head);
    return EXIT_SUCCESS;
}
