#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <public.h>
#include <common_net.h>

int
make_socket_non_blocking(int sfd)
{
    int flags, ret;

    flags = fcntl(sfd, F_GETFL, 0);
    if (-1 == flags)
    {
        ERROR_MSG("fcntl\n");
        goto error;
    }

    flags |= O_NONBLOCK;
    ret = fcntl(sfd, F_SETFL, flags);
    if (-1 == ret)
    {
        ERROR_MSG("fcntl\n");
        goto error;
    }

    return 0;
error:
    return -1;
}

static int
create_and_bind(const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, sfd;

    memset(&hints, 0, sizeof(struct addrinfo));
    /* this protocol family can't be supported by SSL */
    //hints.ai_family = AF_UNSPEC;    /* Return IPv4 and IPv6 choices */
    hints.ai_family = AF_INET;    /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM;    /* We want a TCP socket */
    hints.ai_flags = AI_PASSIVE;    /* All interfaces */

    s = getaddrinfo(NULL, port, &hints, &result);
    if (s)
    {
        ERROR_MSG("getaddrinfo: %s\n", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (-1 == sfd)
            continue;

        s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        if (0 == s)
        {
            /* We managed to bind successfully! */
            break;
        }

        close(sfd);
    }

    if (NULL == rp)
    {
        ERROR_MSG("Could not bind\n");
        return -1;
    }

    freeaddrinfo(result);

    return sfd;
}

int
start_listen(const char *str_port)
{
    int lsfd, ret;

    lsfd = create_and_bind(str_port);
    if (-1 == lsfd) {
        ERROR_MSG("create_and_bind\n");
        goto error;
    }

    ret = make_socket_non_blocking(lsfd);
    if (-1 == ret) {
        ERROR_MSG("make_socket_non_blocking\n");
        goto error;
    }

    ret = listen(lsfd, SOMAXCONN);
    if (-1 == ret) {
        ERROR_MSG("listen\n");
        goto error;
    }

    return lsfd;
error:
    if (lsfd) close(lsfd);
    return -1;
}

int 
connect_srv(const char *ip, unsigned short port)
{
    int sock = 0, ret;
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        ERROR_MSG("sock ERROR\n");
        goto error;
    }

    memset((void *)&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    //addr.sin_family = AF_UNSPEC;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    ret = connect(sock, (struct sockaddr *)&addr, sizeof addr);
    if (ret < 0)
    {
        ERROR_MSG("connect ERROR\n");
        goto error;
    }

    return sock;

error:
    if (sock) close(sock);

    return -1;
}
