#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

int init_OpenSSL(void);

int verify_callback(int ok, X509_STORE_CTX *store);

long post_connection_check(SSL *ssl, char *host);

SSL_CTX *
init_ssl_ctx(char *cert, char *prikey, char *cafile);
