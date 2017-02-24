#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR        "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO       "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT            "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE  "ECE568-SERVER: Incomplete shutdown\n"

#define SERVER_PEM_FILE       "bob.pem"
#define SERVER_PEM_PASS       "password"
#define SERVER_RESPONSE       "42"

int init_socket_listen(int port) {
  int sock;
  int val=1;
  struct sockaddr_in sin;

  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }
  
  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);
  
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
    
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }
  
  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  }

  return sock;
}


/*
 * Initialize SSL context for the server
 */
SSL_CTX *init_server_ctx(char *keyfile, char *password) {
  SSL_CTX *ctx;

  // Initialize common ctx
  ctx = init_ctx(keyfile, password);

  // Server supports SSLv2, SSLv3, TLSv1
  SSL_CTX_set_cipher_list(ctx, "SSLv2:SSLv3:TLSv1");

  // Set verification flags for server, ask client for certificate
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

  return ctx;
}


/*
 * Verify the client certificate
 * Returns: 0 - No certificate or Invalid certificate
 *          1 - Valid certificate
 */
int verify_client_cert(SSL *ssl) {
  int result;
  int size = 256;
  char peer_CN[size];
  char peer_email[size];

  X509 *peer_cert;
  X509_NAME *subject;

  peer_cert = SSL_get_peer_certificate(ssl);
  if (peer_cert != NULL && SSL_get_verify_result(ssl) == X509_V_OK) {
    // Valid certificate
    subject = X509_get_subject_name(peer_cert);
    X509_NAME_get_text_by_NID(subject,
                              NID_commonName,
                              peer_CN,
                              size);
    X509_NAME_get_text_by_NID(subject,
                              NID_pkcs9_emailAddress, 
                              peer_email, 
                              size);
    printf(FMT_CLIENT_INFO, peer_CN, peer_email);
    result = 1;
  } else {
    // No certificate presented or invalid certificate
    printf(FMT_ACCEPT_ERR);
    ERR_print_errors_fp(stdout);
    result = 0;
  }
  return result;
}


/*
 * Handle SSL client request
 * TODO: Need to modify this
 */
int handle_request(SSL *ssl, int s) {
  int result;
  char buf[BUFF_SIZE];
  char *answer = SERVER_RESPONSE;

  // Read from SSL
  result = SSL_read(ssl, buf, BUFF_SIZE);
  switch(SSL_get_error(ssl, result)) {
    case SSL_ERROR_NONE:
      break;
    case SSL_ERROR_ZERO_RETURN:
      goto shutdown;
    case SSL_ERROR_SYSCALL:
      printf(FMT_INCOMPLETE_CLOSE);
      goto done;
    default:
      printf("SSL read problem");
  }
  
  // Write to SSL
  printf(FMT_OUTPUT, buf, answer);
  result = SSL_write(ssl,answer,strlen(answer));
  switch(SSL_get_error(ssl,result)){
    case SSL_ERROR_NONE:
      if(strlen(answer)!=result)
        printf("Incomplete write!");
      break;
    case SSL_ERROR_ZERO_RETURN:
      goto shutdown;
    case SSL_ERROR_SYSCALL:
      printf(FMT_INCOMPLETE_CLOSE);
      goto done;
    default:
      printf("SSL write problem");
  }
  
  shutdown:
  result = SSL_shutdown(ssl);
  if(!result){
    /* If we called SSL_shutdown() first then
       we always get return value of '0'. In
       this case, try again, but first send a
       TCP FIN to trigger the other side's
       close_notify*/
    shutdown(s,1);
    result=SSL_shutdown(ssl);
  }
    
  switch(result){  
    case 1:
      break; /* Success */
    case 0:
    case -1:
    default:
      printf("Shutdown failed");
  }

  done:
  SSL_free(ssl);
  close(s);
  return 0;
}


int main(int argc, char **argv)
{
  int s, sock, port=PORT;
  pid_t pid;
  SSL_CTX *ctx;
  BIO *sbio;
  SSL *ssl;
  
  /*Parse command line arguments*/
  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
        fprintf(stderr,"invalid port number");
        exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  // SSL context would not change for different connections
  ctx = init_server_ctx(SERVER_PEM_FILE, SERVER_PEM_PASS);

  // Initialize socket and listen to port
  sock = init_socket_listen(port);

  while(1){
    
    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }
    
    /* Fork a child to handle the connection*/
    if((pid=fork())){
      close(s);
    } else {
      /* Child code to handle connection*/
      ssl = SSL_new(ctx);
      sbio = BIO_new_socket(s, BIO_NOCLOSE);
      SSL_set_bio(ssl, sbio, sbio);

      if((SSL_accept(ssl) <= 0)) {
        // Error occurred, log and close SSL
        printf(FMT_ACCEPT_ERR);
        ERR_print_errors_fp(stdout);
        close(sock);
        close(s);
        exit (0);
      } else if (verify_client_cert(ssl)) {
        // Handle client request
        handle_request(ssl, s);
      }
      return 0;
    }
  }
  
  close(sock);
  return 1;
}
