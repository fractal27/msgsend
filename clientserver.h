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
       SERVER_SEND_ALL_PUBKEYS        = 0x01,
       SERVER_PUBKEY_NEW              = 0x02,
       SERVER_NOTIFY_DISCONNECT       = 0x03,
       SERVER_RELAY_ENCRYPTED_MESSAGE = 0xff
};
enum value_to_show {
       NO_VALUE,
       VALUE_STRING,
       VALUE_STRING_HEX,
       VALUE_UINT16,
       VALUE_UINT32,
       VALUE_FLOAT,
       VALUE_DOUBLE,
       VALUE_MSGTYPE
};

typedef uint32_t server_message_type_t;

#ifdef DEBUG

void hexdump(const void *buf, size_t len) {
       const unsigned char *p = buf;
       for(size_t i=0;i<len;i++) printf("%02X ", p[i]);
       printf("\n");
}

void
print_msgtype(enum server_message_type message){
       switch(message){
              case SERVER_PUBKEY_NEW:
                     printf("msgtype value: SERVER_PUBKEY_NEW\n");
                     break;
              case SERVER_SEND_ALL_PUBKEYS:
                     printf("msgtype value: SERVER_SEND_ALL_PUBKEYS\n");
                     break;
              case SERVER_RELAY_ENCRYPTED_MESSAGE:
                     printf("msgtype value: SERVER_RELAY_ENCRYPTED_MESSAGE\n");
                     break;
              default:
                     printf("Error: print_msgtype: Unknown msgtype\n");
                     break;
       }
}

bool read_wrap(int sockfd, void* bytes, size_t nbytes, char* label, enum value_to_show valtype)
{
       int result = recv(sockfd,bytes,nbytes,0);
       if(result <= 0){
              return false;
       } else {
              printf("Reading %zu bytes (%10s) from %d into %p\n", nbytes, label, sockfd, bytes);
              switch(valtype){
                     case VALUE_STRING:
                            printf("string value `%*.s`\n", nbytes<200?(int)nbytes:200, (char*)bytes);
                            break;
                     case VALUE_STRING_HEX:
                            printf("bytes value: ");
                            hexdump(bytes,nbytes<200?nbytes:200);
                            break;
                     case VALUE_UINT16:
                            printf("uint16 value: `%hu`\n",*((uint16_t*)bytes)); 
                            break;
                     case VALUE_UINT32:
                            printf("uint32 value: `%u`\n",*((uint32_t*)bytes)); 
                            break;
                     case VALUE_FLOAT:
                            printf("float value: `%f`\n",*((float*)bytes)); 
                            break;
                     case VALUE_DOUBLE: 
                            printf("double value: `%f`\n",*((double*)bytes)); 
                            break;
                     case VALUE_MSGTYPE: 
                            print_msgtype(*((enum server_message_type*)bytes));
                            break;
                     case NO_VALUE:
                            break;
              }
       }
       return true;
}
bool write_wrap(int sockfd, void* bytes, size_t nbytes, char* label, enum value_to_show valtype)
{
       int result = send(sockfd,bytes,nbytes,0);
       if(result <= 0){
              printf("Error while writing %zu bytes (%10s) from %p -> %d\n", nbytes, label, bytes, sockfd);
              return false;
       } else {
              printf("Writing %zu bytes (%10s) from %p -> %d\n", nbytes, label, bytes, sockfd);
              switch(valtype){
                     case VALUE_STRING:
                            printf("string value `%*.s`\n", nbytes<200?(int)nbytes:200, (char*)bytes);
                            break;
                     case VALUE_STRING_HEX:
                            printf("bytes value: ");
                            hexdump(bytes,nbytes<200?nbytes:200);
                            break;
                     case VALUE_UINT16:
                            printf("uint16 value: `%hu`\n",*((uint16_t*)bytes)); 
                            break;
                     case VALUE_UINT32:
                            printf("uint32 value: `%u`\n",*((uint32_t*)bytes)); 
                            break;
                     case VALUE_FLOAT:
                            printf("float value: `%f`\n",*((float*)bytes)); 
                            break;
                     case VALUE_DOUBLE: 
                            printf("double value: `%f`\n",*((double*)bytes)); 
                            break;
                     case VALUE_MSGTYPE:
                            print_msgtype(*((enum server_message_type*)bytes));
                            break;
                     case NO_VALUE:
                            break;
              }
       }
       return true;
}
#else 

#define write_wrap(sockfd, bytes, nbytes, label, valtype) \
       (write(sockfd,bytes,nbytes) > 0)
#define read_wrap(sockfd, bytes, nbytes, label, valtype) \
       (read(sockfd,bytes,nbytes) > 0)

#endif

#endif
