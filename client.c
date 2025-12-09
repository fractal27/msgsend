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
#include "clientserver.h"
#include "gpg-util.h"

struct {
       char username[MAX_USERNAME];
       char* pubkey;
} users[MAX_USERS];

size_t nusers = 0;




pthread_mutex_t mutex_users = PTHREAD_MUTEX_INITIALIZER;


#ifdef DEBUG
bool read_wrap(int sockfd, void* bytes, size_t nbytes, char* label, char* fmt, bool show_value)
{
       int result = recv(sockfd,bytes,nbytes,0);
       if(result < 0){
              return false;
       } else {
              printf("Reading %zu bytes (%10s) from %d into %p\n", nbytes, label, sockfd, bytes);
       }
       return true;
}
bool write_wrap(int sockfd, void* bytes, size_t nbytes, char* label, char* fmt, bool show_value)
{
       int result = send(sockfd,bytes,nbytes,0);
       if(result < 0){
              return false;
       } else {
              printf("Writing %zu bytes (%10s) from %d into %p\n", nbytes, label, sockfd, bytes);
       }
       return true;
}
#else 

#define write_wrap(sockfd, bytes, nbytes, label, fmt, show_value) \
       (write(sockfd,bytes,nbytes) == -1)
#define read_wrap(sockfd, bytes, nbytes, label, fmt, show_value) \
       (read(sockfd,bytes,nbytes) == -1)

#endif


userdata_response_establish
client_establish(int sockfd, char username[40],uint32_t len_pubkey,char* pubkey){
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
       memmove(request,username,ulen);
       printf("to send username: writing %zu bytes\n",sizeof(request));

       if(!write_wrap(sockfd, request, sizeof(request),"establish username","%d",true))  {
              fprintf(stderr,"client_established: write(fd,request,sizeof(request)) failed (Server lost?)\n");
       }
       if(!write_wrap(sockfd, &len_pubkey, sizeof(len_pubkey),"len_pubkey","%d",true))  {
              fprintf(stderr,"client_established: write(fd,&len_pubkey,sizeof(len_pubkey)) failed (Server lost?)\n");
       }
       if(!write_wrap(sockfd, pubkey, len_pubkey, "pubkey", "%d", true))  {
              fprintf(stderr,"client_established: write(fd,pubkey,lenpubkey) failed (Server lost?)\n");
       }


       if(!read_wrap(sockfd, &response, sizeof(response),"establish response", "%x",false)) {
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

void*
thread_read_messages(void* gsockfd){
    enum server_message_type srv_msg_type;
    uint32_t msg_type_len;
    int sockfd = *(int*)gsockfd;

    char username[MAX_USERNAME];
    uint16_t username_len;
    char msg[MAX];
    uint16_t msg_len;

    uint32_t npubkeys;
    uint32_t pubkey_len;
    char* pubkey;


    for(;;){
           if(read_wrap(sockfd, &msg_type_len, sizeof(msg_type_len),"msg_type_len","%u",true)){
                  printf("Arrived here; msg_type_len: %u\n", msg_type_len);
                  if(!read_wrap(sockfd, &srv_msg_type, msg_type_len,"srv_msg_type","%u",true)){
                         fprintf(stderr,"Read error\n");
                         continue;
                  }
                  switch(srv_msg_type){
                         case SERVER_PUBKEY_NEW:
                                if(read_wrap(sockfd, &username_len, sizeof(uint16_t),"username_len","%u",true)
                                              && read_wrap(sockfd, username, username_len,"username","%s",true)
                                              && read_wrap(sockfd, &pubkey_len, sizeof(uint32_t),"pubkey_len","%u",true)){
                                       printf("pubkey_len: %zu\n",(size_t)pubkey_len);
                                       pubkey = (char*)malloc((size_t)pubkey_len+1);
                                       if(!read_wrap(sockfd, pubkey, (size_t)pubkey_len,"pubkey","%s",false)){
                                              printf("Read error from initial public key push");
                                              break;
                                       }
#ifdef DEBUG
                                       printf("pubkey got: `%s`(%zu bytes)\n",pubkey,sizeof(pubkey));
#endif // DEBUG
                                       // pthread_mutex_lock(&mutex_users);
                                       users[nusers].pubkey = pubkey;
                                       memmove(users[nusers].username,username,MAX_USERNAME);
                                       // pthread_mutex_unlock(&mutex_users);
                                       nusers++;
#ifdef DEBUG
                                       printf("--> pubkey added");
                                       printf("nusers: %zu\n",nusers);
#endif // DEBUG
                                }
                                
                                break;
                         case SERVER_SEND_ALL_PUBKEYS:
                                // initial public key push after the establishment of connection.
                                if(!read_wrap(sockfd, &npubkeys, sizeof(uint32_t),"npubkeys","%u",true)){
                                       printf("Read error from initial public key push");
                                       continue;
                                }
                                // printf("Reading %u public keys\n",npubkeys);
                                for(size_t i = 0; i < npubkeys; i++){
                                       if(read_wrap(sockfd, &username_len, sizeof(uint16_t),"username_len","%u",true)
                                       && read_wrap(sockfd, username, username_len,"username","%s",true)
                                       && read_wrap(sockfd, &pubkey_len, sizeof(uint32_t),"pubkey_len","%u",true)){
                                              printf("pubkey_len: %zu\n",(size_t)pubkey_len);
                                              pubkey = (char*)malloc((size_t)pubkey_len+1);
                                              if(!read_wrap(sockfd, pubkey, (size_t)pubkey_len,"pubkey","%s",false)){
                                                     printf("Read error from initial public key push");
                                                     break;
                                              }
#ifdef DEBUG
                                              printf("pubkey got: `%s`(%zu bytes)\n",pubkey,sizeof(pubkey));
#endif // DEBUG
                                              // pthread_mutex_lock(&mutex_users);
                                              users[nusers].pubkey = pubkey;
                                              memmove(users[nusers].username,username,MAX_USERNAME);
                                              // pthread_mutex_unlock(&mutex_users)
                                              nusers++;
#ifdef DEBUG
                                              printf("--> pubkey added");
                                              printf("nusers: %zu\n",nusers);
#endif // DEBUG
                                       }
                                }


                                break;

                         case SERVER_RELAY_ENCRYPTED_MESSAGE:
                                if( !read_wrap(sockfd, &username_len, sizeof(username_len),"username_len","%u",true)
                                 || !read_wrap(sockfd, username, username_len, username,"%s",true)
                                 || !read_wrap(sockfd, &msg_len, sizeof(msg_len),"msg_len","%u",true)
                                 || !read_wrap(sockfd, msg, msg_len,"msg","%s",false)){
                                       fprintf(stderr,"Read error\n");
                                       // shutdown(sockfd,SHUT_RDWR);
                                       // close(sockfd);
                                       // exit(1); __builtin_unreachable();
                                       continue;
                                }
                                decrypt_verify_result_t r = decrypt_and_verify_gpgme(msg);

                                if (r.signature_valid == 0)     printf("\e[33mWARNING: Signature INVALID\e[0m");
                                //else if (r.signature_valid == 1)      printf("Signature VALID (fingerprint: %s)\n", r.signer_fingerprint);
                                else if(r.signature_valid == -1) printf("\e[33mWARNING: No signature found\e[0m");
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
                      printf("Error:  Username is empty\\nn");
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
                             printf("+ Recepient %s (%s)\n", users[i].username, users[i].pubkey);
                             recepients[i] = users[i].pubkey;
                      }
                      recepients[i] = NULL;
               }
        
               gpg_encrypt_and_sign(msg, identity, 1, (const char**)recepients,
                             &msg_enc_signed,&msg_enc_signed_len);
               // printf("signed message: %s",msg_enc_signed);
        
               send(sockfd, &request, sizeof(request), 0);
               send(sockfd, &msg_enc_signed_len, sizeof(uint32_t), 0);
               send(sockfd, msg_enc_signed, msg_enc_signed_len, 0);
               
               // sha256_bytes((uint8_t*)msg_enc_signed, msg_enc_signed_len);
        }
        request.type = TYPE_DISCONNECT;
        bzero(msg,MAX);
        send(sockfd, &request, sizeof(request), 0);
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
