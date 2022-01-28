#ifndef HANR_MSG_H
#define HANR_MSG_H

#include <stdint.h>
#include <arpa/inet.h> 
#include "hanr_client.h"

#define PREFIX 111
#define NEXT_PREFIX 201

#define HANR_EID_LEN 20
#define HANR_NA_LEN 16

enum {
    HANR_MSG_REGISTER_REQUEST = 111,
    HANR_MSG_REGISTER_REPLY = 112,
    HANR_MSG_WITHDRAW_REQUEST = 115,
    HANR_MSG_WITHDRAW_REPLY = 116,
    HANR_MSG_QUERY_REQUEST = 113,
    HANR_MSG_QUERY_REPLY = 114,
};


struct hanr_msg_register_request {
    uint8_t type;
    uint8_t pad;
    uint16_t len;
    uint32_t request_id;
    uint32_t timestamp;
    uint8_t eid[HANR_EID_LEN];
    uint8_t na[HANR_NA_LEN];
}__attribute__((packed));

struct hanr_msg_register_reply {
    uint8_t type;
    uint8_t status;
    uint16_t len;
    uint32_t request_id;
    uint32_t timestamp;
}__attribute__((packed));

struct hanr_msg_query_request {
    uint8_t type;
    uint8_t prefix;
    uint8_t pad;
    uint16_t len;
    uint32_t request_id;
    uint32_t timestamp;
    uint8_t eid[HANR_EID_LEN];
}__attribute__((packed));

struct hanr_msg_query_reply {
    uint8_t type;
    uint8_t status;
    uint16_t len;
    uint32_t request_id;
    uint32_t timestamp;
    uint8_t eid[HANR_EID_LEN];
    uint8_t na[HANR_NA_LEN];
}__attribute__((packed));

struct hanr_msg_withdraw_request {
    uint8_t type;
    uint8_t pad;
    uint16_t len;
    uint32_t request_id;
    uint32_t timestamp;
    uint8_t eid[HANR_EID_LEN];
}__attribute__((packed));

struct hanr_msg_withdraw_reply {
    uint8_t type;
    uint8_t status;
    uint16_t len;
    uint32_t request_id;
    uint32_t timestamp;
}__attribute__((packed));

struct hanr_msg_data{
    uint8_t na[HANR_NA_LEN];
};


static inline void hanr_dump_register_request(struct hanr_msg_register_request *msg)
{
    printf("[REG REQ] Type: %d, Len: %d, RequestID: %u, Timestamp: %u, EID: %s, NA: %s\n", 
            msg->type, ntohs(msg->len), ntohl(msg->request_id), ntohl(msg->timestamp), msg->eid, msg->na);
}

static inline void hanr_dump_register_reply(struct hanr_msg_register_reply *msg)
{
    printf("[REG REP] Type: %d, Len: %d, Status: %d, RequestID: %u, Timestamp: %u\n", 
            msg->type, ntohs(msg->len), msg->status, ntohl(msg->request_id), ntohl(msg->timestamp));
}

static inline void hanr_dump_withdraw_request(struct hanr_msg_withdraw_request *msg)
{
    printf("[WIT REQ] Type: %d, Len: %d, RequestID: %u, Timestamp: %u, EID: %s\n", 
            msg->type, ntohs(msg->len), ntohl(msg->request_id), ntohl(msg->timestamp), msg->eid);
}

static inline void hanr_dump_withdraw_reply(struct hanr_msg_withdraw_reply *msg)
{
    printf("[WIT REP] Type: %d, Len: %d, Status: %d, RequestID: %u, Timestamp: %u\n", 
            msg->type, ntohs(msg->len), msg->status, ntohl(msg->request_id), ntohl(msg->timestamp));   
}

static inline void hanr_dump_query_request(struct hanr_msg_query_request *msg)
{
    printf("[QUE REQ] Type: %d, Len: %d, RequestID: %u, Timestamp: %u, EID: %s\n", 
            msg->type, ntohs(msg->len), ntohl(msg->request_id), ntohl(msg->timestamp), msg->eid);   
}

static inline void hanr_dump_query_reply(struct hanr_msg_query_reply *msg)
{
    printf("[QUE REP] Type: %d, Len: %d, Status: %d, RequestID: %u, Timestamp: %u, EID: %s, NA: %s\n", 
            msg->type, ntohs(msg->len), msg->status, ntohl(msg->request_id), ntohl(msg->timestamp), msg->eid, msg->na);
}

#endif