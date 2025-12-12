#ifndef MSGCNL_CLIENTSERVER_H
#define MSGCNL_CLIENTSERVER_H

#include <stdint.h>

#define MAX 65535
#define PORT 7979
#define MAX_USERS 1024
#define MAX_USERNAME 40
#define MAX_SIMULTANIOUS_SEND 20

typedef struct {
       enum {
              OK                           = (1 << 0),
              ERROR_USERNAME_ALREADY_TAKEN = (1 << 1),
              ERROR_PUBKEY_ALREADY_TAKEN   = (1 << 2),
              ERROR_MAX_USERS_REACHED      = (1 << 3),
              ERROR_USERNAME_EMPTY         = (1 << 4)
       }  status;
} userdata_response_establish;
typedef char userdata_request_establish[MAX_USERNAME];

typedef struct {
       char send_to[MAX_SIMULTANIOUS_SEND][MAX_USERNAME];
       uint32_t nsend_to;
       enum {
              TYPE_SENDTO_ONE  = 0x0001,
              TYPE_SENDTO_MANY = 0x0002,
              TYPE_SENDTO_ALL  = 0x0003,
              TYPE_DISCONNECT  = 0x0004,
       } type;
       uint32_t msg_size;
} userdata_request;


enum server_message_type {
       SERVER_PUBKEY_NEW              = 0x0f,
       SERVER_SEND_ALL_PUBKEYS        = 0xf0,
       SERVER_RELAY_ENCRYPTED_MESSAGE = 0xff,
};

typedef uint32_t server_message_type_t;

#endif
