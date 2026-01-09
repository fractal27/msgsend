#ifndef _SERVER_H
#define _SERVER_H

#include <stdbool.h>
#include <bits/pthreadtypes.h>
#include "shared.h"

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

extern pthread_mutex_t mutex_new_client;
extern client_t clients[MAX_USERS];
extern nclients_t nclients;

void
send_pubkeys(enum pubkey_send_mode mode, int sockfd, char* username, username_len_t username_len, pthread_mutex_t* mutex_lock, server_message_type_t msg_type, pubkey_len_t pubkey_len, char* pubkey);

void
try_send_to(char username_from[MAX_USERNAME], 
              char username_to[MAX_USERNAME], char msg[MAX], 
              username_len_t username_len, msg_len_t msg_len);

void
try_send_to_all(char username_from[MAX_USERNAME], char msg[MAX], 
              username_len_t username_len, msg_len_t msg_len);
void* 
client_handler(void* gclient);

bool
is_socket_connected(int sockfd);

void
threads_cleanup(int signal);

int
server(int sockfd);


#endif // _SERVER_H
