#ifndef l_CLIENT_H
#define l_CLIENT_H

#include "shared.h"

struct user {
       char username[MAX_USERNAME];
       char* pubkey;
       char* fingerprint;
};

extern size_t nusers;

void client(int sockfd, char* identity);

void*
thread_read_messages(void* gsockfd);

void
user_add(char* pubkey, pubkey_len_t pubkey_len, char* username, username_len_t username_len);

userdata_response_establish
client_establish(int sockfd, char username[40],pubkey_len_t len_pubkey,char* pubkey);

#endif // _CLIENT_H
