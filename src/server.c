// server.c //

#include <stdio.h> 
#include <pthread.h>
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <stdbool.h> 
#include <sys/socket.h> 
#include <sys/ioctl.h>
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
       username_len_t username_len;
       char* pubkey;
       pubkey_len_t pubkey_len;
       pthread_mutex_t mutex;
} client_t;

pthread_mutex_t mutex_new_client = PTHREAD_MUTEX_INITIALIZER;

client_t clients[MAX_USERS];
nclients_t nclients = 0;

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


#define pthread_mutex_lock(mutex) pthread_mutex_lock(mutex); printf("%s:%d: Thread %lu: Locking mutex %p\n",__FUNCTION__,__LINE__,pthread_self(),mutex);
#define pthread_mutex_unlock(mutex) pthread_mutex_unlock(mutex); printf("%s:%d:Thread %lu: Unlocking mutex %p\n",__FUNCTION__,__LINE__,pthread_self(),mutex);


// ==================================== Establish functions ===========================================

int
server_establish_client(int connfd, char out_username[MAX_USERNAME],pubkey_len_t* out_pubkey_len, char** out_pubkey){
       userdata_response_establish response;
       userdata_request_establish username_request; // char[40]
       size_t i = 0;
       
       response.status = OK;

       printf("to get username: reading %zu bytes from %i\n",sizeof(username_request),connfd);
       if(!read_wrap(connfd,username_request,sizeof(username_request),"establish username_request",VALUE_STRING)
       || !read_wrap(connfd,out_pubkey_len,SIZE_PUBKEY_LEN,"establish pubkey_len",VALUE_UINT32)){
              printf("Read error: aborting establish connection.\n");
              response.status = ERROR_GENERIC;
              write_wrap(connfd,&response,sizeof(response),"conn. establish response",VALUE_STRING_HEX);
              return ERROR_USERNAME_EMPTY;
       }

       *out_pubkey = malloc((*out_pubkey_len)*sizeof(char));
       read_wrap(connfd,*out_pubkey,*out_pubkey_len,"pubkey",VALUE_STRING);

       if(username_request[0] == '\0') response.status = ERROR_USERNAME_EMPTY;

       client_t* pclient = (client_t*) clients;
       while(i++ < nclients
         && strncmp((pclient)->username,username_request,MAX_USERNAME)
         && strncmp((pclient)->pubkey,*out_pubkey,*out_pubkey_len)) pclient++;

       printf(".... so new public key %s",*out_pubkey);

       if(i != nclients + 1){
              if(strncmp((pclient)->username,username_request,MAX_USERNAME))
                   response.status = ERROR_USERNAME_ALREADY_TAKEN;
              else response.status = ERROR_PUBKEY_ALREADY_TAKEN;
       } else if(nclients == MAX_USERS){
              response.status = ERROR_MAX_USERS_REACHED;
              printf("ERROR: Maximum users reached\n");
       } else {
              memmove(out_username, username_request, MAX_USERNAME);
       }

       write_wrap(connfd,&response,sizeof(response),"conn. establish response",VALUE_STRING_HEX);

       printf("Wrote response.\n");
       return response.status;
}


// ===================== Function for handling connected-socket messages =====================

//
// sends public keys to clients that haven't gotten them yet.
//
void
send_pubkeys(enum pubkey_send_mode mode, int sockfd, char* username, username_len_t username_len, pthread_mutex_t* mutex_lock, server_message_type_t msg_type, pubkey_len_t pubkey_len, char* pubkey){
       printf("============[ Sending public key(s)...]===================\n");
       switch((enum server_message_type) msg_type){
              case SERVER_PUBKEY_NEW:
                     printf("[Server -> Client] Sending SERVER_PUBKEY_NEW\n");
                     switch(mode){
                            case PUBKEY_SEND_ONE:
                                   printf("SEND_ONE\n");
                                   //the linear search is neccessary to find the mutex lock
                                   pthread_mutex_lock(mutex_lock);
                                          if( write_wrap(sockfd,&msg_type,SIZE_MSG_TYPE,"msg_type",VALUE_MSGTYPE)
                                                        && write_wrap(sockfd,&username_len,SIZE_USERNAME_LEN,"username_len",VALUE_UINT16)
                                                        && write_wrap(sockfd,username,(size_t)username_len,"username",VALUE_STRING)
                                                        && write_wrap(sockfd,&pubkey_len,SIZE_PUBKEY_LEN,"pubkey_len",VALUE_UINT32)
                                                        && write_wrap(sockfd,pubkey,pubkey_len,"pubkey",VALUE_STRING)){
                                                 printf("PUBKEY_SEND_ONE: Sent new public key to %i\n",sockfd);
                                          }
                                   pthread_mutex_unlock(mutex_lock);
                                   break;
                            case PUBKEY_SEND_ALL_BUT:
                                   printf("SEND_ALL_BUT\n");
                                   for(nclients_t i = 0; i < nclients; i++){
                                          if(clients[i].sockfd != sockfd){
                                                 // printf("Now checking if the mutex %p is locked: %s\n", &clients[i].mutex, 
                                                 //               pthread_mutex_trylock(&clients[i].mutex)?"Yes":"No");
                                                 pthread_mutex_lock(&clients[i].mutex);
                                                       if(write_wrap(clients[i].sockfd,&msg_type,SIZE_MSG_TYPE,"msg_type",VALUE_MSGTYPE)
                                                         && write_wrap(clients[i].sockfd,&username_len,SIZE_USERNAME_LEN,"username_len",VALUE_UINT8)
                                                         && write_wrap(clients[i].sockfd,username,(size_t)username_len,"username",VALUE_STRING)
                                                         && write_wrap(clients[i].sockfd,&pubkey_len,SIZE_PUBKEY_LEN,"pubkey_len",VALUE_UINT32)
                                                         && write_wrap(clients[i].sockfd,pubkey,pubkey_len,"pubkey",VALUE_STRING)){
                                                               printf("PUBKEY_SEND_ALL_BUT: Sent new public key to %i\n",sockfd);
                                                        }
                                                 pthread_mutex_unlock(&clients[i].mutex);
                                          }
                                   }
                                   break;
                            default:
                                   break;
                     }
                     printf("[Server -> Client] Done\n");
                     break;
              case SERVER_SEND_ALL_PUBKEYS:
                     printf("[Server -> Client] Sending SERVER_SEND_ALL_PUBKEYS\n");
                     bool flag = false;
                     nclients--;
                     pthread_mutex_lock(mutex_lock);
                            if(write_wrap(sockfd,&msg_type,SIZE_MSG_TYPE,"msg_type",VALUE_MSGTYPE)
                            && write_wrap(sockfd,&nclients,SIZE_NPUBKEYS,"npubkeys",VALUE_UINT16)){
                                   nclients++;
                                   flag = true;
                                   // printf("passed msg_type:%u, nclients:%u\n",msg_type, nclients);
                                   for(nclients_t i = 0; i < nclients; i++){
                                          if(clients[i].sockfd != sockfd
                                          && write_wrap(sockfd,&clients[i].username_len,SIZE_USERNAME_LEN,"username_len",VALUE_UINT8)
                                          && write_wrap(sockfd,clients[i].username,clients[i].username_len,"username",VALUE_STRING)
                                          && write_wrap(sockfd,&clients[i].pubkey_len,SIZE_PUBKEY_LEN,"pubkey_len",VALUE_UINT32)
                                          && write_wrap(sockfd,clients[i].pubkey,clients[i].pubkey_len,"pubkey",VALUE_STRING)){
                                                 printf("username_len:%u\n",clients[i].username_len);
                                                 printf("pubkey_len: %u\n",pubkey_len);
                                                 printf("Sent client information of %d to client %d\n",clients[i].sockfd,sockfd);
                                          }
                                   }
                            }
                     pthread_mutex_unlock(mutex_lock);
                     if(!flag) nclients++;
                     // this trick of nclients-- nclients++ has to be done to let know the client that he only needs to take nclients-1 pubkey messages.
                     // TODO: this could be avoided simply in the client code taking the value and using value-1
                     printf("[Server -> Client] Done\n");
                     break;
              //TODO: implement
              //case SERVER_PUBKEY_UPDATE:
              //     break;
              case SERVER_NOTIFY_DISCONNECT:
                     fprintf(stderr,"\e[33mWarning: send_pubkeys: This function should be used only for public keys exchanges. Sending SERVER_NOTIFY_DISCONNECT packets is NOT the use case for it.\n\e[0m");
                     return;
              case SERVER_RELAY_ENCRYPTED_MESSAGE:
                     fprintf(stderr,"\e[33mWarning: send_pubkeys: This function should be used only for public keys exchanges. Sending SERVER_RELAY_ENCRYPTED_MESSAGE packets is NOT the use case for it.\n\e[0m");
                     return;
       }
       printf("==================[ DONE ]===================\n");
}
void
try_send_to(char username_from[MAX_USERNAME], char username_to[MAX_USERNAME], char msg[MAX], 
                                                   username_len_t username_len, msg_len_t msg_len){
       server_message_type_t msg_type = SERVER_RELAY_ENCRYPTED_MESSAGE;
       if(username_from == username_to) return;

       for(nclients_t i = 0; i < nclients; i++){
              client_t client = clients[i];
              if(!strncmp(client.username, username_to, username_len)){ //send
                     pthread_mutex_lock(&client.mutex);
                              if(!write_wrap(client.sockfd, &msg_type, SIZE_MSG_TYPE,"msg_type",VALUE_STRING_HEX)
                              || !write_wrap(client.sockfd, &username_len, SIZE_USERNAME_LEN,"username_len",VALUE_UINT16)
                              || !write_wrap(client.sockfd, username_from, username_len,"username_from",VALUE_STRING)
                              || !write_wrap(client.sockfd, &msg_len, SIZE_MSG_LEN,"msg_len",VALUE_UINT16)
                              || !write_wrap(client.sockfd, msg, msg_len,"msg",VALUE_STRING_HEX)){
                                   fprintf(stderr,"Error while writing.\n");
                            } else printf("Sent message '%*.s' to '%s'\n",(int)msg_len,msg,client.username);
                     pthread_mutex_unlock(&client.mutex);
              }
       }
}

void
try_send_to_all(char username_from[MAX_USERNAME], char msg[MAX], username_len_t username_from_len, msg_len_t msg_len){
       server_message_type_t msg_type = SERVER_RELAY_ENCRYPTED_MESSAGE;

       printf("==================[ BEGIN SENDTO_ALL %s ]===================\n", username_from);
       for(size_t i = 0; i < nclients; i++){
              client_t client = clients[i];
              printf("checking msg: (%s -> %s)\n",username_from,client.username);
              if(strcmp(client.username,username_from)){
                     printf("Check OK: 1: sending message\n");
                     pthread_mutex_lock(&client.mutex);
                            printf("Check OK: 2: sending message\n");
                            if( !write_wrap(client.sockfd, &msg_type, SIZE_MSG_TYPE,"msg_type",VALUE_STRING_HEX)
                             || !write_wrap(client.sockfd, &username_from_len, SIZE_USERNAME_LEN,"username_from_len",VALUE_UINT16)
                             || !write_wrap(client.sockfd, username_from, username_from_len,"username_from",VALUE_STRING)
                             || !write_wrap(client.sockfd, &msg_len, SIZE_MSG_LEN,"msg_len",VALUE_UINT16)
                             || !write_wrap(client.sockfd, msg, msg_len,"msg",VALUE_STRING_HEX)){
                                   fprintf(stderr,"Error while writing.\n");
                            } else {
                                   printf("Sent message '%s' to '%s'\n",msg,client.username);
                            }
                     pthread_mutex_unlock(&client.mutex);
                     printf("Done.\n");
              }
       }
       printf("==================[ DONE SENDTO_ALL ]===================\n");
}

void* 
client_handler(void* gclient) 
{ 
       client_t* client = (client_t*)gclient;
       int connfd = client->sockfd;
       char username[MAX_USERNAME];
       char* pubkey;
       pubkey_len_t pubkey_len;
       userdata_request request;

       if(server_establish_client(connfd, username,&pubkey_len,&pubkey) != OK){
              printf("Aborting connection\n");
              close(connfd);
              return NULL; // abort client-server connection
       }


       username_len_t username_len = strlen(username)+1;

       msg_len_t msglen;
       char msg[MAX];

       printf("Initializing mutex for username %s\n",username);
       pthread_mutex_lock(&mutex_new_client);
              memmove(client->username,username,username_len);
              client->pubkey = pubkey;
              client->pubkey_len = pubkey_len;
              client->username_len = username_len;
              if(pthread_mutex_init(&client->mutex, NULL) != 0){
                     printf("failed to initialize client's mutex\n");
                     return NULL;
              }
              printf("Initialized mutex %p from user with username %s\n",&client->mutex,username);
       pthread_mutex_unlock(&mutex_new_client);

       nclients++; // nclients Global 

       // pthread_mutex_lock(&mutex_public_keys);
       //        public_keys[npublic_keys++]= pubkey;
       // pthread_mutex_unlock(&mutex_public_keys);

       send_pubkeys(0, connfd, username, username_len, &client->mutex, SERVER_SEND_ALL_PUBKEYS, pubkey_len, pubkey);
       send_pubkeys(PUBKEY_SEND_ALL_BUT, connfd, username, username_len, &client->mutex, SERVER_PUBKEY_NEW, pubkey_len, pubkey);

       printf("Connection established with client\n");

       // infinite loop for chat 
       int count = 0;
       bool success;

       for (;;) {
              // checks count in read buffer of socket
              count = 0;
              while(count <= 0) {
                     ioctl(client->sockfd, FIONREAD, &count);
                     usleep(100);
              }
              success = false;
              pthread_mutex_lock(&client->mutex); // syncronyzed with client mutex
              if((success = read_wrap(connfd, &request, sizeof(request),"client request", VALUE_STRING_HEX))){
                     printf("unique_ptr 1\n");
                     success = read_wrap(connfd, &msglen, SIZE_MSG_LEN,"msglen",VALUE_UINT16);
                     printf("unique_ptr 2\n");
              }
              pthread_mutex_unlock(&client->mutex);

              if(success){
                     if(msglen > MAX){
                            printf("Error: Msglen exceeded max.\n");
                            continue;
                     }
                     if(!read_wrap(connfd, msg, msglen,"msg",VALUE_STRING)){
                            printf("Error while reading message\n");
                            continue;
                     }
                     if(!is_socket_connected(connfd)){
                            goto disconnect;
                     }
                     // printf("from '%s': %s\ntype: ", username, request.msg);
                     msg[MAX-1] = '\0';
                     switch(request.type){
                            case TYPE_SENDTO_ONE:
                                   printf("Type: Send one\n");
                                   username_len_t to_send_username_len;
                                   char to_send_username[MAX_USERNAME];

                                   if(read_wrap(connfd, &to_send_username_len, SIZE_USERNAME_LEN, "username_len", VALUE_STRING)
                                   && read_wrap(connfd, &to_send_username, to_send_username_len, "username_len", VALUE_STRING))
                                          try_send_to(username, to_send_username, msg, username_len, msglen);
                                   break;

                            case TYPE_SENDTO_MANY:
                                   printf("Type: Send many\n");
                                   for(size_t i = 0; i < request.nsend_to; i++){
                                          if(read_wrap(connfd, &to_send_username_len, SIZE_USERNAME_LEN, "username_len", VALUE_STRING)
                                          && read_wrap(connfd, &to_send_username, to_send_username_len, "username_len", VALUE_STRING))
                                                 try_send_to(username, to_send_username, msg, username_len, msglen);
                                   }
                                   break;

                            case TYPE_SENDTO_ALL:
                                   printf("Type: Send all\n");
                                   try_send_to_all(username, msg, username_len, msglen);
                                   break;

                            case TYPE_DISCONNECT:
                                   printf("Client '%s' disconnected\n",username);
                                   goto disconnect;

                            default:
                                   printf("Message wrongfully constructed.\n");
                                   goto disconnect;

                     }
              } 
       }
disconnect:
       printf("Disconnecting %s (socket %d)\n",username,client->sockfd);
       close(connfd);
       free(client->pubkey);
       pthread_mutex_unlock(&client->mutex);
       pthread_mutex_destroy(&client->mutex);
       memmove(client,client+1,nclients-(client-clients)-1);
       nclients--;
       enum server_message_type msg_type = SERVER_NOTIFY_DISCONNECT;
       for(client_t* pclient = clients; pclient-clients < nclients; pclient++){
              pthread_mutex_lock(&pclient->mutex);
              if (write_wrap(pclient->sockfd,&msg_type,SIZE_MSG_TYPE,"msg_type",VALUE_MSGTYPE)
                && write_wrap(pclient->sockfd,&pclient->username_len,SIZE_USERNAME_LEN,"username_len",VALUE_UINT16)
                && write_wrap(pclient->sockfd,pclient->username,pclient->username_len,"username",VALUE_STRING_HEX)){
                     printf("Disconnect notified to %s\n",pclient->username);
              }
              pthread_mutex_unlock(&pclient->mutex);
       }
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
                     printf("Server accept failed...\n"); 
                     continue;
              } else printf("Server accept the client...\n"); 
              clients[nclients] = (client_t){ .sockfd = connfd };
              pthread_create(&clients[nclients].thread, NULL, client_handler, &clients[nclients]);
       }
       // After chatting close the socket 
       close(sockfd); 
}
