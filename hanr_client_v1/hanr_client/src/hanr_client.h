#ifndef HANR_CLIENT_H
#define HANR_CLIENT_H

#include <stdint.h>
#include <stdbool.h>

#include <rte_mempool.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

// 400 kpps
#define HANR_MAX_RATE 400000

#define NUM_MBUFS 81920
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_PKT_BURST 32

enum {
    HANR_MSG_REGISTER = 1,
    HANR_MSG_WITHDRAW = 2,
    HANR_MSG_QUERY = 3,
    HANR_MSG_MAX = 4,
};

#define HANR_EID_LEN 20
#define HANR_NA_LEN 16



struct hanr_lcore_port_queue
{
    uint32_t lcore_id;
    uint16_t port_id;
    uint16_t queue_id;
};

struct hanr_client_conf
{
    int msgtype;
    int count;
    int rate;
    int verbose;
    struct rte_mempool *rx_pool;
    struct rte_mempool *tx_pool;
    struct hanr_lcore_port_queue rxq[RTE_MAX_LCORE];
    struct hanr_lcore_port_queue txq[RTE_MAX_LCORE];
};

int hanr_tx_main(void *arg);

int hanr_rx_main(void *arg);

int hanr_client_process_tx(struct hanr_client_conf* conf,
                          struct rte_mbuf** bufs,
                          int burst);

int hanr_client_process_rx(struct hanr_client_conf *conf, struct rte_mbuf *buf);


extern volatile bool hanr_quit;
extern struct hanr_client_conf hanr_conf;
#endif