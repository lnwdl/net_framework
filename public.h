#ifndef __PUBLIC_H__
#define __PUBLIC_H__

#include <stdio.h>

#define ERROR_MSG(format, ...) \
    fprintf(stderr, ""__FILE__"|%d|"format"", __LINE__, ##__VA_ARGS__)

#define MAX_EVENTS 64
#define MAX_CONNECTIONS 64

#define SRV_CERTFILE "/home/wangdeliang/certs/cert_srv.crt"
#define SRV_PRIKEY "/home/wangdeliang/certs/pri_srv.pem"
#define SRV_CAFILE "/home/wangdeliang/certs/cert_root.crt"

#define CLI_CAFILE "/home/wangdeliang/certs/cert_root.crt"
#define CLI_CERTFILE "/home/wangdeliang/certs/cert_cli.crt"
#define CLI_PRIKEY "/home/wangdeliang/certs/pri_cli.pem"

#endif
