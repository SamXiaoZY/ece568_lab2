#ifndef _common_h
#define _common_h "system_1.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#define CA_FILE		"568ca.pem"
#define PORT		8765
#define BUFF_SIZE	256

SSL_CTX *init_ctx(char *keyfile, char *password);
int password_cb(char *buf, int size, int rwflag, void *password);

#endif