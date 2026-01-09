#ifndef MSGCNL_CLIENTSERVER_H
#define MSGCNL_CLIENTSERVER_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <limits.h>
#include <stdio.h>

#define MAX 65535
#define PORT 7878
#define MAX_USERS 1024
#define MAX_USERNAME 40
#define MAX_SIMULTANIOUS_SEND 20

#define SIZE_USERNAME_LEN  sizeof(uint8_t)  // max 255 (should be 40 but there isn't any shorter)
#define SIZE_MSG_LEN       sizeof(uint16_t) // max 65535
#define SIZE_PUBKEY_LEN    sizeof(uint32_t) // max 4M
#define SIZE_MSG_TYPE      sizeof(uint32_t) // max 4M
#define SIZE_NCLIENTS      sizeof(uint16_t) // max 65535
#define SIZE_NPUBKEYS      SIZE_NCLIENTS // uint16_t


#define LOG_BASE(log_level_str, format, ...) do {\
                struct timespec ts;\
                clock_gettime(CLOCK_REALTIME,&ts);\
                fprintf(stderr,"[ %3jd.%3ld] ",((intmax_t)ts.tv_sec % 3600) / 60, ts.tv_nsec / 1000000);\
                fprintf(stderr, __BASE_FILE__ ": " log_level_str format __VA_OPT__(,) __VA_ARGS__);\
       } while(0);


#ifndef DEBUG_MODE
#define LOG_DEBUG(...)
#else  // DEBUG_MODE
#define LOG_DEBUG(format, ...)       LOG_BASE("(\e[34mDEBUG\e[0m) ", format __VA_OPT__(,) __VA_ARGS__) 
#endif // DEBUG_MODE
#define LOG_INFO(format, ...)        LOG_BASE("(\e[1mINFO\e[0m)  ", format __VA_OPT__(,) __VA_ARGS__) 
#define LOG_NOTICE(format, ...)      LOG_BASE("(\e[33mNOTICE\e[0m)", format __VA_OPT__(,) __VA_ARGS__) 
#define LOG_WARNING(format, ...)     LOG_BASE("(\e[33;1mWARN\e[0m)  ", format __VA_OPT__(,) __VA_ARGS__) 
#define LOG_ERROR(format, ...)       LOG_BASE("(\e[31mERROR\e[0m) ", format __VA_OPT__(,) __VA_ARGS__)


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


void hexdump(const void *buf, size_t len);
void print_msg(enum value_to_show valtype, void* bytes, size_t nbytes);
bool read_wrap(int sockfd, void* bytes, size_t nbytes, char* label, enum value_to_show valtype);
bool write_wrap(int sockfd, void* bytes, size_t nbytes, char* label, enum value_to_show valtype);

#else 

#define write_wrap(sockfd, bytes, nbytes, label, valtype) \
       (write(sockfd,bytes,nbytes) > 0)
#define read_wrap(sockfd, bytes, nbytes, label, valtype) \
       (read(sockfd,bytes,nbytes) > 0)

#endif

#endif // MSGCNL_CLIENTSERVER_H
