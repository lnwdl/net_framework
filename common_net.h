#ifndef __COMMON_NET_H__
#define __COMMON_NET_H__

int
make_socket_non_blocking(int sfd);

int
start_listen(const char *str_port);

int 
connect_srv(const char *ip, unsigned short port);

#endif
