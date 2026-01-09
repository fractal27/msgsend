#ifdef DEBUG
#include "shared.h"

#include <sys/socket.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

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
#endif //DEBUG
