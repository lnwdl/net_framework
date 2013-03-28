#include <public.h>
#include <common_ssl.h>

int
init_OpenSSL(void)
{
    if (!SSL_library_init())
    {
        ERROR_MSG("** OpenSSL initialization failed!\n");
        return -1;
    }

    SSL_load_error_strings();

    return 0;
}

int verify_callback(int ok, X509_STORE_CTX *store)
{
    char data[256];

    if (!ok)
    {
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int depth = X509_STORE_CTX_get_error_depth(store);
        int err = X509_STORE_CTX_get_error(store);
        ERROR_MSG("certificate at deth: %i\n", depth);

        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        ERROR_MSG("issuer = %s\n", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        ERROR_MSG("subject = %s\n", data);
        ERROR_MSG("error_no: %i\n, error_msg: %s\n", err,
                X509_verify_cert_error_string(err));
    }

    return ok;
}

long post_connection_check(SSL *ssl, char *host)
{
    X509 *cert;
    X509_NAME *subj;
    char data[256];
    int extcount;
    int ok = 0;

    /* checking the return from SSL_get_peer_certificate here is not
     * strictly necessary. With our example programs, it is not 
     * possible for it to return NULL. However, it is good form to 
     * check the return since it can return NULL if the examples are
     * modified to enalbe anonymous ciphers or for the server to not
     * require a client certificate.
     */
    if (!(cert = SSL_get_peer_certificate(ssl)) || !host) {
        goto err_occured;
    }

    if ((extcount = X509_get_ext_count(cert)) > 0)
    {
        int i;
        for (i = 0; i < extcount; ++i)
        {
            char *extstr;
            X509_EXTENSION *ext;

            ext = X509_get_ext(cert, i);
            extstr = (char *)OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));
            if (!strcmp(extstr, "subjectAltName"))
            {
                int j;
                unsigned char *data;
                STACK_OF(CONF_VALUE) *val;
                CONF_VALUE *nval;
                X509V3_EXT_METHOD *meth;

                if (!(meth = (X509V3_EXT_METHOD *)X509V3_EXT_get(ext)))
                    break;
                data = ext->value->data;

                val = meth->i2v(meth,
                        meth->d2i(NULL, (const unsigned char **)&data, ext->value->length),
                        NULL);
                for (j = 0; j < sk_CONF_VALUE_num(val); ++j)
                {
                    nval = sk_CONF_VALUE_value(val, j);
                    if (!strcmp(nval->name, "DNS")
                        && !strcmp(nval->value, host))
                    {
                        ok = 1;
                        break;
                    }
                }
            }
            if (ok)
                break;
        }
    }

    if (!ok && (subj = X509_get_subject_name(cert)) &&
        X509_NAME_get_text_by_NID(subj, NID_commonName, data, 256) > 0)
    {
        data[255] = 0;
        if (strcasecmp(data, host) != 0)
        {
            ERROR_MSG("========================\n");
            ERROR_MSG("CommonName: %s\n", data);
            ERROR_MSG("host: %s\n", host);
            ERROR_MSG("========================\n");
            goto err_occured;
        }
    }

    X509_free(cert);

    return SSL_get_verify_result(ssl);
err_occured:
    if (cert)
        X509_free(cert);

    return X509_V_ERR_APPLICATION_VERIFICATION;
}

SSL_CTX *
init_ssl_ctx(char *cert, char *prikey, char *cafile) 
{
    SSL_CTX *ctx = NULL;

    ctx = SSL_CTX_new(SSLv23_method());
    if (NULL == ctx) {
        ERROR_MSG("SSL_CTX_new\n");
        goto error;
    }

    if (SSL_CTX_load_verify_locations(ctx, cafile, NULL) != 1) {
        ERROR_MSG("SSL_CTX_load_verify_loacations\n");
        goto error;
    }

    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        ERROR_MSG("SSL_ctx_set_default_verify_path\n");
        goto error;
    }

    if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1) {
        ERROR_MSG("SSL_CTX_use_certificate_chain_file\n");
        goto error;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, prikey, SSL_FILETYPE_PEM) != 1) {
        ERROR_MSG("SSL_CTX_use_PrivateKey_file\n");
        goto error;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
            verify_callback);

    SSL_CTX_set_verify_depth(ctx, 4);
    
    /* set session cache */
    SSL_CTX_set_session_id_context(ctx, (unsigned char *)"lnwdl", sizeof("lnwdl"));

    return ctx;

error:
    if (ctx) SSL_CTX_free(ctx);
    return NULL;
}

