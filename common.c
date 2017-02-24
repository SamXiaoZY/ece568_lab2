#include "common.h"

static char *pem_password;

SSL_CTX *init_ctx(char *keyfile, char *password);
int password_cb(char *buf, int size, int rwflag, void *password);

/*
 * Initialize ctx
 */
SSL_CTX *init_ctx(char *keyfile, char *password) {
  SSL_CTX *ctx;
  
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();

  /* Create context*/
  ctx = SSL_CTX_new(SSLv23_method());
  SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);

  /* Load certificate and private key */
  SSL_CTX_use_certificate_chain_file(ctx, keyfile);
  SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM);

/* Set pem password */
  pem_password = password;
  SSL_CTX_set_default_passwd_cb(ctx, password_cb);

  /* Load trusted CA's*/
  SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL);

  return ctx;
}


/*
 * Callback function for setting default pem password when initializing ctx
 */
int password_cb(char *buf, int size, int rwflag, void *password) {
  strncpy(buf, pem_password, size);
  buf[size - 1] = '\0';
  return(strlen(buf));
}

