// client.c
// client: receives messages indefinately.
#include <limits.h>
#include <sys/socket.h>
#include <arpa/inet.h> // inet_addr()
#include <stdbool.h>
#include <strings.h> // bzero()
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h> // read(), write(), close()
#include <stdarg.h>
#include <netdb.h>
#include <stdio.h>
#include <stddef.h>
#include "clientserver.h"
#include "gpg-util.h"

struct {
       char username[MAX_USERNAME];
       char* pubkey;
       char* fingerprint;
} users[MAX_USERS];

size_t nusers = 0;



pthread_mutex_t mutex_users = PTHREAD_MUTEX_INITIALIZER;



userdata_response_establish
client_establish(int sockfd, char username[40],pubkey_len_t len_pubkey,char* pubkey){
       if(pubkey == NULL){
              fprintf(stderr,"client_establish: Invalid public key: key is NULL\n");
              exit(1);
       }

       userdata_response_establish response;
       userdata_request_establish request;

       int c; while ((c = getchar()) != '\n' && c != EOF) /* discard */ ;

       printf("Choose a unique username(40 characters max): ");
       fgets(username, MAX_USERNAME, stdin);
       size_t ulen = strlen(username)-1;

       if(ulen == -1) ulen = 0;
       username[ulen] = '\0';
       memmove(request,username,ulen+1);
       // printf("to send username: writing %zu bytes\n",sizeof(request));

       if(!write_wrap(sockfd, request, sizeof(request),"establish username",VALUE_STRING_HEX/**/))  {
              fprintf(stderr,"client_established: write(fd,request,sizeof(request)) failed (Server lost?)\n");
       }
       if(!write_wrap(sockfd, &len_pubkey, SIZE_PUBKEY_LEN,"len_pubkey",VALUE_UINT32))  {
              fprintf(stderr,"client_established: write(fd,&len_pubkey,sizeof(len_pubkey)) failed (Server lost?)\n");
       }
       if(!write_wrap(sockfd, pubkey, len_pubkey, "pubkey", VALUE_UINT32))  {
              fprintf(stderr,"client_established: write(fd,pubkey,lenpubkey) failed (Server lost?)\n");
       }


       if(!read_wrap(sockfd, &response, sizeof(response),"establish response", VALUE_STRING_HEX)) {
              fprintf(stderr,"client_established: read(fd,buf,n) failed  (Server lost?)\n");
       }

       return response;
}

// bool
// is_socket_connected(int sockfd){
//        int error = 0;
//        socklen_t len = sizeof (error);
//        int retval = getsockopt (sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
//        if(retval != 0){
//               fprintf(stderr, "error getting socket error code: %s\n", strerror(retval));
//               return false;
//        } else if (error != 0){
//               fprintf(stderr, "socket error: %s\n", strerror(error));
//               return false;
//        }
//        return true;
// }










void
user_add(char* pubkey, pubkey_len_t pubkey_len, char* username, username_len_t username_len){
#ifdef DEBUG
       printf("pubkey got: `%s`(%zu bytes)\n",pubkey,sizeof(pubkey));
#endif // DEBUG
       // pthread_mutex_lock(&mutex_users);
       char* fpr;
       if(import_key(pubkey,pubkey_len,&fpr) < 0){
              printf("No fingerprint available\n");
              return;
       }
       users[nusers].fingerprint = fpr;
       users[nusers].pubkey = pubkey;
       memmove(users[nusers].username,username,MAX_USERNAME);
       // pthread_mutex_unlock(&mutex_users);
       nusers++;
#ifdef DEBUG
       printf("--> pubkey added with fingerprint %s\n",fpr);
       printf("nusers: %zu\n",nusers);
#endif // DEBUG
}

void*
thread_read_messages(void* gsockfd){
    server_message_type_t srv_msg_type;
    int sockfd = *(int*)gsockfd;

    char username[MAX_USERNAME];
    username_len_t username_len;
    char msg[MAX];
    msg_len_t msg_len;

    npubkeys_t npubkeys;
    pubkey_len_t pubkey_len;
    char* pubkey;


    for(;;){
           if(read_wrap(sockfd, &srv_msg_type, SIZE_MSG_TYPE,"srv_msg_type",VALUE_MSGTYPE)){
                  switch(srv_msg_type){
                         case SERVER_PUBKEY_NEW:
                                if(read_wrap(sockfd, &username_len, SIZE_USERNAME_LEN,"username_len",VALUE_UINT16)
                                && read_wrap(sockfd, username, username_len,"username",VALUE_STRING_HEX/**/)
                                && read_wrap(sockfd, &pubkey_len, SIZE_PUBKEY_LEN,"pubkey_len",VALUE_UINT32)){
                                       // printf("pubkey_len: %zu\n",(size_t)pubkey_len);
                                       pubkey = (char*)malloc((size_t)pubkey_len+1);
                                       if(!read_wrap(sockfd, pubkey, (size_t)pubkey_len,"pubkey",VALUE_STRING_HEX/**/)){
                                              fprintf(stderr,"Read error from initial public key push");
                                              break;
                                       }
                                       user_add(pubkey,pubkey_len,username,username_len);
                                }
                                
                                break;
                         case SERVER_NOTIFY_DISCONNECT:
                                // notifies of the disconnect of another client, so that we remove that from the list.
                                if(read_wrap(sockfd, &username_len,SIZE_USERNAME_LEN,"username_len",VALUE_UINT16)
                                && read_wrap(sockfd,username,username_len,"username",VALUE_STRING_HEX/**/)){
                                       for(nclients_t client_idx = 0; client_idx < nusers; client_idx++)
                                       {
                                              if(!strncmp(username,users[client_idx].username,username_len)){
                                                     printf("User %s disconnected\n",username); 
                                                     memmove(&users[client_idx],&users[client_idx]+1,nusers-client_idx-1);
                                                     nusers--;
                                                     break;
                                              }
                                       }
                                }

                                break;
                         case SERVER_SEND_ALL_PUBKEYS:
                                // initial public key push after the establishment of connection.
                                if(!read_wrap(sockfd, &npubkeys, SIZE_NPUBKEYS, "npubkeys",VALUE_UINT32)){
                                       printf("Read error from initial public key push");
                                       continue;
                                }
                                // printf("Reading %u public keys\n",npubkeys);
                                for(npubkeys_t i = 0; i < npubkeys; i++){
                                       if(read_wrap(sockfd, &username_len, SIZE_USERNAME_LEN,"username_len",VALUE_UINT16)
                                       && read_wrap(sockfd, username, username_len,"username",VALUE_STRING_HEX/**/)
                                       && read_wrap(sockfd, &pubkey_len, SIZE_PUBKEY_LEN,"pubkey_len",VALUE_UINT32)){
                                              // printf("pubkey_len: %zu\n",(size_t)pubkey_len);
                                              pubkey = (char*)malloc((size_t)pubkey_len+1);
                                              if(!read_wrap(sockfd, pubkey, (size_t)pubkey_len,"pubkey",VALUE_STRING_HEX/**/)){
                                                     printf("Read error from initial public key push");
                                                     break;
                                              }
                                              user_add(pubkey,pubkey_len,username,username_len);
                                       }
                                }


                                break;

                         case SERVER_RELAY_ENCRYPTED_MESSAGE:
                                if( !read_wrap(sockfd, &username_len, SIZE_USERNAME_LEN,"username_len",VALUE_UINT16)
                                 || !read_wrap(sockfd, username, username_len, username,VALUE_STRING_HEX/**/)
                                 || !read_wrap(sockfd, &msg_len, SIZE_MSG_LEN,"msg_len",VALUE_UINT16)
                                 || msg_len > 65535
                                 || !read_wrap(sockfd, msg, msg_len,"msg",VALUE_STRING_HEX/**/)){
                                       fprintf(stderr,"Read error\n");
                                       // shutdown(sockfd,SHUT_RDWR);
                                       // close(sockfd);
                                       // exit(1); __builtin_unreachable();
                                       continue;
                                }
                                decrypt_verify_result_t r = decrypt_and_verify_gpgme(msg);

                                if (r.signature_valid == 0)     
                                {
                                       printf("\e[33mWARNING: Signature INVALID\e[0m");
                                }
                                //else if (r.signature_valid == 1)      printf("Signature VALID (fingerprint: %s)\n", r.signer_fingerprint);
                                else if(r.signature_valid == -1) {
                                       printf("\e[33mWARNING: No signature found\e[0m");
                                }
                                printf("\n[\e[32m%s\e[0m]: %s\n", username, r.plaintext);
                                free(r.plaintext);
                                free(r.signer_fingerprint);
                                break;
                  }
           }
    }
}

void client(int sockfd)
{
       pthread_t thread_read;
       char msg[MAX];
       char username[40];
       int n;
       userdata_request request;

       
       char* identity = userinput_identity_can_encrypt();
       printf("chosen identity %s\n",identity);
       if(identity == NULL){
              fprintf(stderr, "Error: identity is null.\n");
              return;
       }
        char* pubkey = export_public_key(identity);
        printf("public key sent to server: %s\n",pubkey);
        userdata_response_establish response = client_establish(sockfd, username, strlen(pubkey), pubkey);
        pthread_create(&thread_read, NULL, thread_read_messages, &sockfd);
        switch(response.status){
               case ERROR_MAX_USERS_REACHED:
                      printf("Error:  Server has reached the max possible users.\n");
                      return;
               case ERROR_PUBKEY_ALREADY_TAKEN:
                      printf("Error:  Public key is already taken\n");
                      break;
               case ERROR_USERNAME_ALREADY_TAKEN:
                      printf("Error:  Username is already taken\n");
                      return;
               case ERROR_USERNAME_EMPTY:
                      printf("Error:  Username is empty\n");
                      return;
               case ERROR_GENERIC:
                      printf("Server error: Generic\n");
                      return;
               case OK:
                      printf("Connection established\n");
                      break;
        }
        
        for (;;) {
               size_t msg_enc_signed_len;
               char* msg_enc_signed;
        
               bzero(msg, sizeof(msg));
               printf("(\e[34;1m%s\e[0m) :  ", username);
        
               fgets(msg,MAX,stdin);
               while(!nusers) usleep(100000);
               n = strlen(msg)-1;
               if(n == 0) continue; // just \n
               msg[n] = '\0';
               request.type = TYPE_SENDTO_ALL;
               // TODO: Change request.type based on the message
               // Ex: @someone @anotherone ecc..
        
               if ((strncmp(msg, "exit", 4)) == 0) {
                      printf("Client Exit...\n");
                      break;
               }
               char* recepients[MAX_USERS+1] = {NULL};
               if(request.type == TYPE_SENDTO_ALL){
                      size_t i;
                      printf("nusers: %zu\n",nusers);
                      for(i = 0; i < nusers; i++){
                             printf("+ Recepient %s (%s)\n", users[i].username, users[i].fingerprint);
                             recepients[i] = users[i].fingerprint;
                      }
                      recepients[i] = NULL;
               }
        
               gpg_encrypt_and_sign(msg, identity, 1, (const char**)recepients,
                             &msg_enc_signed,&msg_enc_signed_len);
               // printf("signed message: %s",msg_enc_signed);
        
               send(sockfd, &request, sizeof(request), 0);
               send(sockfd, &msg_enc_signed_len, SIZE_MSG_LEN, 0);
               send(sockfd, msg_enc_signed, msg_enc_signed_len, 0);
               
               // sha256_bytes((uint8_t*)msg_enc_signed, msg_enc_signed_len);
        }

        // NTS: don't know if neccessary to cleanup
        // information leak.
        // bzero(msg,MAX);

        request.type = TYPE_DISCONNECT;
        send(sockfd, &request, sizeof(request), 0);
        // close(sockfd);
        free(pubkey);
        free(identity);
}

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
       client(sockfd);

       // close the socket
       close(sockfd);
}
