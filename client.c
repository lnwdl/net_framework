#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <public.h>
#include <common_net.h>
#include <common_ssl.h>

int ssl_cli_loop(SSL *ssl)
{
    ssize_t rdlen;
    char data[80];
    int ret, err;

    for (;;) {
        bzero(data, sizeof(data));

        /* get string from stdin */
        if (!fgets(data, sizeof(data), stdin)) {
            break;
        }

        /* write the string to peer */
        ret = SSL_write(ssl, data, strlen(data));
        if (ret <= 0) {
            err = SSL_get_error(ssl, ret);
            if (err != SSL_ERROR_WANT_READ 
                    && err != SSL_ERROR_WANT_WRITE) {
                ERROR_MSG("SSL_write error_no: %d\n", err);
                goto error;
            }
        }

        /* write the peer's reply to stdout */
        rdlen = SSL_read(ssl, data, sizeof(data));
        if (rdlen < 0) {
            ERROR_MSG("SSL_read error\n");
            goto error;
        }
        data[rdlen] = 0;
        printf("read==> %s\n", data);
    }

    return 0;

error:
    return -1;
}

int main(int argc, char *argv[])
{
    int fd = 0;
    unsigned short port;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int err;

    if (argc != 3) {
        printf("Usage: %s ip port\n", argv[0]);
        goto error;
    }

    if (init_OpenSSL() != 0) {
        ERROR_MSG("init_OpenSSL\n");
        goto error;
    }

    ctx = init_ssl_ctx(CLI_CERTFILE, CLI_PRIKEY, CLI_CAFILE);
    if (NULL == ctx) {
        ERROR_MSG("init_ssl_ctx\n");
        goto error;
    }

    port = (unsigned short)atoi(argv[2]);
    fd = connect_srv(argv[1], port);
    if (fd < 0) {
        ERROR_MSG("connect_srv\n");
        goto error;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_connect(ssl);
    err = post_connection_check(ssl, "192.168.1.10");
    if (err != X509_V_OK) {
        ERROR_MSG("post_connection_check error\n");
        ERROR_MSG("-Error: peer certificate: %s\n", 
                X509_verify_cert_error_string(err));
        goto error;
    }

    if (ssl_cli_loop(ssl) < 0) {
        ERROR_MSG("cli_loop stop\n");
        goto error;
    }

error:
    if (ssl) SSL_shutdown(ssl);
    if (ssl) SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);
    if (fd) close(fd);

    return 0;
}
