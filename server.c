// server.c //

#include <stdio.h> 
#include <pthread.h>
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <stdbool.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h> // read(), write_wrap(), close()
#include "clientserver.h"


enum pubkey_send_mode{
    PUBKEY_SEND_ONE,
    PUBKEY_SEND_ALL_BUT,
};


typedef struct {
       pthread_t thread;
       int sockfd;
       char username[MAX_USERNAME];
       uint32_t username_len;
       char* pubkey;
       uint32_t pubkey_len;
       bool free_to_ow;
} client_t;

// char* public_keys[512];
// uint32_t npublic_keys;


client_t clients[MAX_USERS];
uint32_t nclients = 0;

uint32_t sent_to = 0;
// bool message_to_send = false;
// pthread_mutex_t mutex_public_keys = PTHREAD_MUTEX_INITIALIZER;

// ==================================== Util functions ===========================================

bool
is_socket_connected(int sockfd){
       int error = 0;
       socklen_t len = sizeof (error);
       int retval = getsockopt (sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
       if(retval != 0){
              fprintf(stderr, "error getting socket error code: %s\n", strerror(retval));
              return false;
       } else if (error != 0){
              fprintf(stderr, "socket error: %s\n", strerror(error));
              return false;
       }
       return true;
}

#ifdef DEBUG
void hexdump(const void *buf, size_t len) {
           const unsigned char *p = buf;
           for(size_t i=0;i<len;i++) printf("%02X ", p[i]);
           printf("\n");
}

bool write_wrap(int sockfd, void* bytes, size_t nbytes, char* label)
{
       int result = write(sockfd,bytes,nbytes);
       if(result < 0){
              return false;
       } else if(result > 0) {
              printf("Writing %zu bytes (%10s) from %d into %p\n", nbytes, label, sockfd, bytes);
              hexdump(bytes,nbytes<200?nbytes:200);
       }
       return true;
}
bool read_wrap(int sockfd, void* bytes, size_t nbytes, char* label)
{
       int result = read(sockfd,bytes,nbytes);
       if(result < 0){
              return false;
       } else if(result > 0) {
              printf("Reading %zu bytes (%10s) from %d into %p\n", nbytes, label, sockfd, bytes);
              hexdump(bytes,nbytes<200?nbytes:200);
       }
       return true;
}
#else // DEBUG

#define read_wrap(sockfd,bytes,nbytes,label)  (read(sockfd,bytes,nbytes) == -1)
#define write_wrap(sockfd,bytes,nbytes,label) (write(sockfd,bytes,nbytes) == -1)

#endif // DEBU

// ==================================== Establish functions ===========================================

int
server_establish_client(int connfd, char out_username[MAX_USERNAME],uint32_t* out_pubkey_len, char** out_pubkey){
       userdata_response_establish response;
       userdata_request_establish username_request; // char[40]
       size_t i = 0;
       
       response.status = OK;

       printf("to get username: reading %zu bytes from %i\n",sizeof(username_request),connfd);
       read(connfd,username_request,sizeof(username_request));
       read(connfd,out_pubkey_len,sizeof(uint32_t));
       *out_pubkey = malloc((*out_pubkey_len)*sizeof(char));
       read(connfd,*out_pubkey,*out_pubkey_len);

       if(username_request[0] == '\0') response.status = ERROR_USERNAME_EMPTY;

       client_t* pclient = (client_t*) clients;
       while(i++ < nclients
         && strncmp((pclient)->username,username_request,MAX_USERNAME)) pclient++;
         // && strncmp((pclient)->pubkey,*out_pubkey,*out_pubkey_len)) pclient++;;

       printf(".... so new public key %s",*out_pubkey);

       if(i != nclients + 1){
              if(strncmp((pclient)->username,username_request,MAX_USERNAME))
                   response.status = ERROR_USERNAME_ALREADY_TAKEN;
              else response.status = ERROR_PUBKEY_ALREADY_TAKEN;
              // printf("*out_pubkey_len: %u\n",*out_pubkey_len);
              // printf("(pubkey,other_pubkey,...): %s\n",(pclient)->pubkey);
              // printf("%s--------------------------\n",*out_pubkey);
              // printf("i: %zu\n",i);
       } else if(nclients == MAX_USERS){
              response.status = ERROR_MAX_USERS_REACHED;
              printf("ERROR: Maximum users reached\n");
       } else {
              memmove(out_username, username_request, MAX_USERNAME);
       }

       write_wrap(connfd,&response,sizeof(response),"conn. establish response");

       printf("Wrote response.\n");
       return response.status;
}


// ===================== Function for handling connected-socket messages =====================

//
// sends public keys to clients that haven't gotten them yet.
//
void
send_pubkeys(enum pubkey_send_mode mode, int sockfd, char* username, uint16_t username_len, server_message_type_t msg_type, uint32_t pubkey_len, char* pubkey){
       uint32_t msg_type_len = (uint32_t)sizeof(msg_type);
       printf("Sending public key(s)...\n");
       switch((enum server_message_type) msg_type){
              case SERVER_PUBKEY_NEW:
                     printf("[Server -> Client] Sending SERVER_PUBKEY_NEW\n");
                     switch(mode){
                            case PUBKEY_SEND_ONE:
                                   if(write_wrap(sockfd,&msg_type_len,sizeof(uint32_t),"msg_type_len")
                                   && write_wrap(sockfd,&msg_type,msg_type_len,"msg_type")
                                   && write_wrap(sockfd,&username_len,sizeof(uint16_t),"username_len")
                                   && write_wrap(sockfd,username,(size_t)username_len,"username")
                                   && write_wrap(sockfd,&pubkey_len,sizeof(uint32_t),"pubkey_len")
                                   && write_wrap(sockfd,pubkey,pubkey_len,"pubkey")){
                                          printf("PUBKEY_SEND_ONE: Sent new public key to %i\n",sockfd);
                                   }
                                   break;
                            case PUBKEY_SEND_ALL_BUT:
                                   for(uint32_t i = 0; i < nclients; i++){
                                          if(clients[i].sockfd != sockfd){
                                                 if(write_wrap(clients[i].sockfd,&msg_type_len,sizeof(uint32_t),"msg_type_len")
                                                  && write_wrap(clients[i].sockfd,&msg_type,msg_type_len,"msg_type")
                                                  && write_wrap(clients[i].sockfd,&username_len,sizeof(uint16_t),"username_len")
                                                  && write_wrap(clients[i].sockfd,username,(size_t)username_len,"username")
                                                  && write_wrap(clients[i].sockfd,&pubkey_len,sizeof(uint32_t),"pubkey_len")
                                                  && write_wrap(clients[i].sockfd,pubkey,pubkey_len,"pubkey")){
                                                        printf("PUBKEY_SEND_ALL_BUT: Sent new public key to %i\n",sockfd);
                                                 }
                                          }
                                   }
                                   break;
                     }
                     printf("[Server -> Client] Done\n");
                     break;
              case SERVER_SEND_ALL_PUBKEYS:
                     printf("[Server -> Client] Sending SERVER_SEND_ALL_PUBKEYS\n");
                     bool flag = false;
                     nclients--;
                     if(write_wrap(sockfd,&msg_type_len,sizeof(uint32_t),"msg_type_len")
                     && write_wrap(sockfd,&msg_type,msg_type_len,"msg_type")
                     && write_wrap(sockfd,&nclients,sizeof(uint32_t),"nclients")){
                            nclients++;
                            flag = true;
                            printf("passed msg_type_len:%u, msg_type:%u, nclients:%u\n",msg_type_len, msg_type, nclients);
                            for(uint32_t i = 0; i < nclients; i++){
                                   printf("writing msg_type_len: %u\n",msg_type_len);
                                   if(clients[i].sockfd != sockfd
                                   && write_wrap(sockfd,&clients[i].username_len,sizeof(uint16_t),"username_len")
                                   && write_wrap(sockfd,clients[i].username,clients[i].username_len,"username")
                                   && write_wrap(sockfd,&clients[i].pubkey_len,sizeof(uint32_t),"pubkey_len")
                                   && write_wrap(sockfd,clients[i].pubkey,clients[i].pubkey_len,"pubkey")){
                                          printf("username_len:%u\n",clients[i].username_len);
                                          printf("pubkey_len: %u\n",pubkey_len);
                                          printf("Sent client information of %d to client %d\n",clients[i].sockfd,sockfd);
                                   }
                            }
                     }
                     if(!flag) nclients++;
                     printf("[Server -> Client] Done\n");
                     break;
              //TODO: implement
              //case SERVER_PUBKEY_UPDATE:
              //     break;
              case SERVER_RELAY_ENCRYPTED_MESSAGE:
                     fprintf(stderr,"\e[33mWarning: send_pubkeys: This function should be used only for public keys exchanges. Sending SERVER_RELAY_ENCRYPTED_MESSAGE packets is NOT the use case for it.\n\e[0m");
                     return;
       }
}
void
try_send_to(char username_from[MAX_USERNAME], char username_to[MAX_USERNAME], char msg[MAX], 
                                                   uint16_t username_len, uint16_t msg_len){
       server_message_type_t msg_type = SERVER_RELAY_ENCRYPTED_MESSAGE;
       uint32_t msg_type_size = (uint32_t) sizeof(msg_type);
       if(username_from == username_to) return;

       for(size_t i = 0; i < nclients; i++){
              client_t client = clients[i];
              if(!strncmp(client.username, username_to, username_len)){ //send
                     if( write_wrap(client.sockfd, &msg_type_size, sizeof(uint32_t),"msg_type_size")
                       || write_wrap(client.sockfd, &msg_type, sizeof(msg_type),"msg_type")
                       || write_wrap(client.sockfd, &username_len, sizeof(uint16_t),"username_len")
                       || write_wrap(client.sockfd, username_from, username_len,"username_from")
                       || write_wrap(client.sockfd, &msg_len, sizeof(msg_len),"msg_len")
                       || write_wrap(client.sockfd, msg, msg_len,"msg")){
                            fprintf(stderr,"Error while writing.\n");
                     } else printf("Sent message '%*.s' to '%s'\n",(int)msg_len,msg,client.username);
              }
       }
}

void
try_send_to_all(char username_from[MAX_USERNAME], char msg[MAX], uint16_t username_from_len, uint16_t msg_len){
       server_message_type_t msg_type = SERVER_RELAY_ENCRYPTED_MESSAGE;
       uint32_t msg_type_size = (uint32_t) sizeof(msg_type);

       for(size_t i = 0; i < nclients; i++){
              client_t client = clients[i];
              printf("msg: (%s -> %s)\n",username_from,client.username);
              if(strcmp(client.username,username_from)){
                     if(write_wrap(client.sockfd, &msg_type_size, sizeof(uint32_t),"msg_type_size")
                      || write_wrap(client.sockfd, &msg_type, sizeof(msg_type),"msg_type")
                      || write_wrap(client.sockfd, &username_from_len, sizeof(username_from_len),"username_from_len")
                      || write_wrap(client.sockfd, username_from, username_from_len,"username_from")
                      || write_wrap(client.sockfd, &msg_len, sizeof(msg_len),"msg_len")
                      || write_wrap(client.sockfd, msg, msg_len,"msg")){
                            fprintf(stderr,"Error while writing.\n");
                     } else {
                            printf("Sent message '%s' to '%s'\n",msg,client.username);
                     }
              }
       }
}

void* 
client_handler(void* gclient) 
{ 
       client_t* client = (client_t*)gclient;
       int connfd = client->sockfd;
       char username[MAX_USERNAME];
       char* pubkey;
       uint32_t pubkey_len;
       userdata_request request;

       if(server_establish_client(connfd, username,&pubkey_len,&pubkey) != OK){
              printf("Aborting connection\n");
              close(connfd);
              return NULL; // abort client-server connection
       }

       nclients++; // nclients Global 

       uint16_t username_len = strlen(username)+1;

       uint32_t msglen;
       char msg[MAX];

       memmove(client->username,username,username_len);
       client->pubkey = pubkey;
       client->pubkey_len = pubkey_len;
       client->username_len = username_len;

       // pthread_mutex_lock(&mutex_public_keys);
       //        public_keys[npublic_keys++]= pubkey;
       // pthread_mutex_unlock(&mutex_public_keys);

       send_pubkeys(0, connfd, username, username_len, SERVER_SEND_ALL_PUBKEYS, pubkey_len, pubkey);
       send_pubkeys(PUBKEY_SEND_ALL_BUT, connfd, username, username_len, SERVER_PUBKEY_NEW, pubkey_len, pubkey);

       printf("Connection established with client\n");

       // infinite loop for chat 
       for (;;) { 
              if(read_wrap(connfd, &request, sizeof(request),"client request") &&
                 read_wrap(connfd, &msglen, sizeof(msglen),"msglen")) {
                     if(msglen > MAX){
                            printf("Error: Msglen exceeded max.\n");
                            continue;
                     }
                     read_wrap(connfd, msg, msglen,"msg");
                     if(!is_socket_connected(connfd)){
                            printf("Client '%s' disconnected\n",username);
                            close(connfd);
                            free(client->pubkey);
                            memmove(client,client+1,nclients-(client-clients)-1);
                            nclients--;
                            return NULL;
                     }
                     // printf("from '%s': %s\ntype: ", username, request.msg);
                     msg[MAX-1] = '\0';
                     switch(request.type){
                            case TYPE_SENDTO_ONE:
                                   printf("send 1\n");
                                   try_send_to(username, request.send_to[0], msg, username_len, msglen);
                                   break;

                            case TYPE_SENDTO_MANY:
                                   printf("send many\n");
                                   for(size_t i = 0; i < request.nsend_to; i++){
                                          try_send_to(username, request.send_to[i], msg, username_len, msglen);
                                   }
                                   break;

                            case TYPE_SENDTO_ALL:
                                   printf("send all\n");
                                   try_send_to_all(username, msg, username_len, msglen);
                                   break;

                            case TYPE_DISCONNECT:
                                   printf("Client '%s' disconnected\n",username);

                            default:
                                   printf("Message wrongfully constructed.\n");
                                   goto disconnect;
                                   break;

                     }
              }
       } 
disconnect:
       close(connfd);
       free(client->pubkey);
       memmove(client,client+1,nclients-(client-clients)-1);
       return NULL;
} 

// Driver function 
int main() 
{ 
       int sockfd, connfd; 
       socklen_t len;
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
       else
              printf("Socket successfully binded..\n"); 

       // Now server is ready to listen and verification 
       if ((listen(sockfd, 5)) != 0) { 
              printf("Listen failed...\n"); 
              exit(0); 
       } 
       else
              printf("Server listening..\n"); 
       len = sizeof(cli); 

       while(1){
              // Accept the data packet from client and verification 
              if (nclients == MAX_USERS) { 
                printf("Max users reached: Accept must be rejected\n");
                while(nclients == MAX_USERS) usleep(1.2e6);
                if(nclients == MAX_USERS){
                       // probably just keyboard interrupt while in `while` loop
                       break;
                }
              }
              connfd = accept(sockfd, (struct sockaddr*)&cli, &len); 
              if (connfd < 0) { 
                     printf("server accept failed...\n"); 
                     continue;
              } 
              else printf("server accept the client...\n"); 
              clients[nclients] = (client_t){ .sockfd = connfd };
              pthread_create(&clients[nclients].thread, NULL, client_handler, &clients[nclients]);
       }
       // After chatting close the socket 
       close(sockfd); 
}
