#include <limits.h>
#include <sys/socket.h>
#include <arpa/inet.h> // inet_addr()
#include <stdbool.h>
#include <strings.h> // bzero()
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h> // read(), write(), close()
#include <stdarg.h>
#include <netdb.h>
#include <stdio.h>
#include <stddef.h>
#include "client.h"

#include "gpg-util.h"

void die(const char* msg, ...){
       va_list args;
       va_start(args, msg);
       vfprintf(stderr,msg,args);
       exit(1);
       __builtin_unreachable();
}


int main(int argc, char** argv)
{
       int sockfd;
       struct sockaddr_in servaddr;

       // socket create and verification
       sockfd = socket(AF_INET, SOCK_STREAM, 0);
       if (sockfd == -1) {
              printf("socket creation failed...\n");
              exit(0);
       }
       else printf("Socket successfully created..\n");
       bzero(&servaddr, sizeof(servaddr));

       // assign IP, PORT
       servaddr.sin_family = AF_INET;
       if(argc >= 2) servaddr.sin_addr.s_addr = inet_addr(argv[1]);
       else die("No server address provided");
       if(argc >= 3) servaddr.sin_port = htons(atoi(argv[2]));
       else servaddr.sin_port = htons(PORT);

       // connect the client socket to server socket
       if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
              printf("connection with the server failed...\n");
              exit(1);
       } else printf("connected to the server..\n");
       setup(); // setup encryption

       // function for chat
       client(sockfd,NULL);

       // close the socket
       close(sockfd);
}
