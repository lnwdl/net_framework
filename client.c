#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/bio.h>

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
    BIO *sess_file;
    SSL_SESSION *sess, *new_sess;

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
    /* using saved session start */
    sess_file = BIO_new_file(SESSION_FILE, "r");
    if (!sess_file) {
        printf("The saved session is not found\n");
    } else {
        printf("Use the saved session for SSL connection\n");
        sess = PEM_read_bio_SSL_SESSION(sess_file, NULL, 0, NULL);
        BIO_free(sess_file);
        if (!sess) {
            printf("Can't open session file %s\n", SESSION_FILE);
        } else {
            SSL_set_session(ssl, sess);
            printf("save session->sid_ctx: %s\n", sess->sid_ctx);
            SSL_SESSION_free(sess);
        }
    }
    /* using saved session end */
    SSL_connect(ssl);
    err = post_connection_check(ssl, "192.168.1.10");
    if (err != X509_V_OK) {
        ERROR_MSG("post_connection_check error\n");
        ERROR_MSG("-Error: peer certificate: %s\n", 
                X509_verify_cert_error_string(err));
        goto error;
    }

    /* save new session to file start */
    new_sess = SSL_get_session(ssl);
    sess_file = BIO_new_file(SESSION_FILE, "w");
    if (!new_sess || !sess_file) {
        printf("save session open session or file error\n");
    } else {
        printf("save session to file\n");
        PEM_write_bio_SSL_SESSION(sess_file, new_sess);
        BIO_free(sess_file);
    }
    /* save new session to file end */

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
