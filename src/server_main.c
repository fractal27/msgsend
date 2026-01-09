#include <stdio.h>
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
#include "server.h"

// Driver function 
int main() 
{ 
       int sockfd, connfd; 
       __socklen_t len;
       struct sockaddr_in servaddr, cli; 

       // socket create and verification 
       int opt = 1;
       sockfd = socket(AF_INET, SOCK_STREAM, 0); 
       setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

       if (sockfd == -1) { 
              printf("socket creation failed...\n"); 
              exit(0); 
       } 
       else
              printf("Socket successfully created..\n"); 

       // assign IP, PORT 
       servaddr.sin_family = AF_INET; 
       servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
       servaddr.sin_port = htons(PORT); 

       // Binding newly created socket to given IP and verification 
       if ((bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0) { 
              printf("socket bind failed...\n"); 
              exit(0); 
       } 
       printf("Socket successfully binded on port %d..\n",PORT); 

       // Now server is ready to listen and verification 
       if ((listen(sockfd, 5)) != 0) { 
              printf("Listen failed...\n"); 
              exit(0); 
       } 
       else
              printf("Server listening..\n"); 

       return server(sockfd);
}

