#ifndef MSGCNL_CLIENTSERVER_H
#define MSGCNL_CLIENTSERVER_H

#include <stdint.h>
#include <time.h>
#include <limits.h>

#define MAX 65535
#define PORT 7979
#define MAX_USERS 1024
#define MAX_USERNAME 40
#define MAX_SIMULTANIOUS_SEND 20

#define SIZE_USERNAME_LEN  sizeof(uint8_t)  // max 255 (should be 40 but there isn't any shorter)
#define SIZE_MSG_LEN       sizeof(uint16_t) // max 65535
#define SIZE_PUBKEY_LEN    sizeof(uint32_t) // max 4M
#define SIZE_MSG_TYPE      sizeof(uint32_t) // max 4M
#define SIZE_NCLIENTS      sizeof(uint16_t) // max 65535
#define SIZE_NPUBKEYS      SIZE_NCLIENTS // uint16_t


typedef uint8_t username_len_t;
typedef uint16_t msg_len_t;
typedef uint32_t pubkey_len_t;
typedef uint32_t msg_type_t;
typedef uint32_t nclients_t;
typedef nclients_t npubkeys_t; // uint32_t


typedef union {
       enum {
              OK                           = (1 << 0),
              ERROR_USERNAME_ALREADY_TAKEN = (1 << 1),
              ERROR_PUBKEY_ALREADY_TAKEN   = (1 << 2),
              ERROR_MAX_USERS_REACHED      = (1 << 3),
              ERROR_USERNAME_EMPTY         = (1 << 4),
              ERROR_GENERIC                = (1 << 5),
       }  status;
} userdata_response_establish;
typedef char userdata_request_establish[MAX_USERNAME];

typedef struct {
       enum {
              TYPE_SENDTO_ONE  = 0x0001,
              TYPE_SENDTO_MANY = 0x0002,
              TYPE_SENDTO_ALL  = 0x0003,
              TYPE_DISCONNECT  = 0x0004,
       } type;
       uint32_t msg_size;
       uint32_t nsend_to;
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
       VALUE_UINT8,
       VALUE_UINT16,
       VALUE_UINT32,
       VALUE_FLOAT,
       VALUE_DOUBLE,
       VALUE_MSGTYPE
};

typedef uint32_t server_message_type_t;

#ifdef DEBUG


#define printf(x,...) \
       do {\
              struct timespec ts;\
              clock_gettime(CLOCK_REALTIME,&ts);\
              printf("[ %3jd.%3ld] ",((intmax_t)ts.tv_sec % 3600) / 60, ts.tv_nsec / 1000000);\
              printf(x __VA_OPT__(,) __VA_ARGS__);\
       } while(0);


void hexdump(const void *buf, size_t len) {
       const unsigned char *p = buf;
       for(size_t i=0;i<len;i++){
              fprintf(stderr,"%02X ", p[i]);
       }
       fprintf(stderr,"\n");
}

void print_msg(enum value_to_show valtype, void* bytes, size_t nbytes){
       switch(valtype){
              case VALUE_STRING:
                     printf("string value `%*.s`\n", nbytes<200?(int)nbytes:200, (char*)bytes);
                     break;
              case VALUE_STRING_HEX:
                     printf("bytes value: ");
                     hexdump(bytes,nbytes<200?nbytes:200);
                     break;
              case VALUE_UINT8:
                     printf("uint8 value: `%hhu`\n",*((uint8_t*)bytes)); 
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
                     switch(*((enum server_message_type*)bytes)){
                            case SERVER_PUBKEY_NEW:
                                   printf("msgtype value: SERVER_PUBKEY_NEW\n");
                                   break;
                            case SERVER_SEND_ALL_PUBKEYS:
                                   printf("msgtype value: SERVER_SEND_ALL_PUBKEYS\n");
                                   break;
                            case SERVER_RELAY_ENCRYPTED_MESSAGE:
                                   printf("msgtype value: SERVER_RELAY_ENCRYPTED_MESSAGE\n");
                                   break;
                            case SERVER_NOTIFY_DISCONNECT:
                                   printf("msgtype value: SERVER_NOTIFY_DISCONNECT\n");
                                   break;
                            default:
                                   printf("Error: print_msgtype: Unknown msgtype(Data sent misaligned?)\n");
                                   break;
                     }
                     break;
              case NO_VALUE:
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
              print_msg(valtype,bytes,nbytes);
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
              print_msg(valtype,bytes,nbytes);
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
