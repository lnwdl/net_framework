
CC =	gcc
CFLAGS =  -W -Wall -Werror -g 
TARGET = cli srv
INCPATH = .
LIBPATH = /home/wangdeliang/openssl/soft/lib

all: $(TARGET)

cli:
	$(CC) $(CFLAGS) -o cli client.c common_ssl.c common_net.c \
		-l ssl -l crypto -I $(INCPATH) -L $(LIBPATH)
srv:
	$(CC) $(CFLAGS) -o srv server.c common_ssl.c common_net.c connection.c \
		-l ssl -l crypto -I $(INCPATH) -L $(LIBPATH)
clean:
	rm -rf $(TARGET)
