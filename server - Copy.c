#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

int main(int argc, char **argv)
{
  int s, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  pid_t pid;
  
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
  
  while(1){
    
    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }
    
    /*fork a child to handle the connection*/
    
    if(pid=fork()){
      close(s);
    }
    else {
      /*Child code*/
      int len;
      char buf[256];
      char *answer = "42";

      len = recv(s, &buf, 255, 0);
      buf[len]= '\0';
      printf(FMT_OUTPUT, buf, answer);
      send(s, answer, strlen(answer), 0);
      close(sock);
      close(s);
      return 0;
    }
  }
  
  close(sock);
  return 1;
}



void InitializeSSL()
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
}

void DestroySSL()
{
    ERR_free_strings();
    EVP_cleanup();
}

void ShutdownSSL()
{
    SSL_shutdown(ssl);
    SSL_free(ssl);
}


int sockfd, newsockfd;
SSL_CTX *sslctx;
SSL *cSSL;

InitializeSSL();
sockfd = socket(AF_INET, SOCK_STREAM, 0);
if (sockfd< 0)
{
    //Log and Error
    return;
}
struct sockaddr_in saiServerAddress;
bzero((char *) &saiServerAddress, sizeof(saiServerAddress));
saiServerAddress.sin_family = AF_INET;
saiServerAddress.sin_addr.s_addr = serv_addr;
saiServerAddress.sin_port = htons(aPortNumber);

bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));

listen(sockfd,5);
newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

sslctx = SSL_CTX_new( SSLv23_server_method());
SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);
int use_cert = SSL_CTX_use_certificate_file(sslctx, "/serverCertificate.pem" , SSL_FILETYPE_PEM);

int use_prv = SSL_CTX_use_PrivateKey_file(sslctx, "/serverCertificate.pem", SSL_FILETYPE_PEM);

cSSL = SSL_new(sslctx);
SSL_set_fd(cSSL, newsockfd );
//Here is the SSL Accept portion.  Now all reads and writes must use SSL
ssl_err = SSL_accept(cSSL);
if(ssl_err <= 0)
{
    //Error occurred, log and close down ssl
    ShutdownSSL();
}

//You are then able read or write using: 
SSL_read(cSSL, (char *)charBuffer, nBytesToRead);
SSL_write(cSSL, "Hi :3\n", 6);