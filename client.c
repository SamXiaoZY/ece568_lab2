#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "common.h"

#define HOST "localhost"
#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

#define PASSWORD "password"
#define CLIENT_PEM_FILE "alice.pem"
#define SERVER_NAME "Bob's Server"
#define SERVER_EMAIL "ece568bob@ecf.utoronto.ca"


int OpenConnection(const char *host, int port) {
  int sock;
  struct hostent *gethostname;
  struct sockaddr_in myaddr;

  gethostname = gethostbyname(host);

  if (gethostname == NULL){
    perror("cannot get host name!");
  }


  memset(&myaddr,0,sizeof(myaddr));
  myaddr.sin_addr=*(struct in_addr *)gethostname->h_addr_list[0];
  myaddr.sin_family=AF_INET;
  myaddr.sin_port=htons(port);


  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(myaddr.sin_addr),port);

  /*set socket*/
  if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0){
    perror("socket is not created!\n");
  }
  if (connect(sock, (struct sockaddr*)&myaddr, sizeof(myaddr))!=0){
    close(sock);
    perror("cannot connect!");
    exit(0);
  }

  return sock;
}



void verify_server_cert(SSL *ssl){
  X509 *cert;
  X509_NAME *name;
  char server_CN[256];
  char server_emailaddr[256];
  char server_CA[256];


  //check if the certificate is valid
  if(SSL_get_verify_result(ssl) != X509_V_OK){
    perror(FMT_NO_VERIFY);

  }

  cert = SSL_get_peer_certificate(ssl);
  name = X509_get_issuer_name(cert);

  if(cert == NULL){
    perror(FMT_NO_VERIFY);
    exit(0);
  }

  X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, server_CN,256);
  X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_pkcs9_emailAddress, server_emailaddr,256);
  X509_NAME_get_text_by_NID(name, NID_commonName, server_CA,256);

  //check server name
  if(strcasecmp(server_CN,SERVER_NAME)){
    perror(FMT_CN_MISMATCH);
    exit(0);
  }

  //check email address
  if(strcasecmp(server_emailaddr,SERVER_EMAIL)){
    perror(FMT_EMAIL_MISMATCH);
    exit(0);
  }

  printf(FMT_SERVER_INFO, server_CN, server_emailaddr, server_CA);

}

//copied from Sam
/*
 * Handle SSL client request
 * TODO: Need to modify this
 */
void handle_request(SSL *ssl, char* secret, char* buf) {
  int len;
  int request;
  int n;

  request = strlen(secret);

  n = SSL_write(ssl, secret, request);
  switch(SSL_get_error(ssl,n)){
    case SSL_ERROR_NONE:
      if(request != n)
        perror("write incomplete!");
      break;
    default:
      perror("SSL write problem");
  }

  len = SSL_read(ssl, buf, 256);
  if(len < 0)
    perror("read problem!");
  buf[len] = '\0';
  
}



int main(int argc, char **argv)
{
  int len, sock, port=PORT;
  char *host=HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char buf[256];
  char *secret = "What's the question?";
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
        fprintf(stderr,"invalid port number");
        exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }
  

  SSL_CTX *ctx;
  ctx = init_ctx(CLIENT_PEM_FILE, PASSWORD);

  //Only communicate with servers using SSLv3 or TLSv1.
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

  //Only communicate with a protocol that uses the SHA1 hash function.
  SSL_CTX_set_cipher_list(ctx, "SHA1");

  sock = OpenConnection(host, port);

  SSL *ssl;
  BIO *sbio;

  ssl = SSL_new(ctx);
  //return BIO using sock and close_flag
  sbio = BIO_new_socket(sock, BIO_NOCLOSE);

  /*
  connects the BIOs rbio and wbio for the read and 
  write operations of the TLS/SSL (encrypted) side of ssl
  */
  SSL_set_bio(ssl, sbio, sbio);


  //initiates the TLS/SSL handshake with a serve
  if(SSL_connect(ssl) != 1){
    perror("TLS/SSL handshake is unsuccessful!\n");
    ERROR_print_errors_fp(stdout);
  }

  //check server's certificate
  verify_server_cert(ssl);
  handle_request(ssl, secret, buf);

  printf(FMT_OUTPUT, secret, buf); 
 
if(SSL_shutdown(ssl) == 0){
  perror(FMT_INCORRECT_CLOSE);
}

SSL_free(ssl)
SSL_CTX_free(ctx);
close(sock);
return 0;

}
