#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hanr_client.h"
#include "hanr_msg.h"
#include "hanr_packet_generator.h"

static volatile int hanr_request_id = 0;

static inline int hanr_client_create_packet(struct rte_mempool* mp,
                                            struct rte_mbuf** bufs,
                                            int idx,
                                            uint8_t* msg,
                                            uint16_t msglen) {
    struct rte_ether_hdr pkt_eth_hdr;
    struct rte_ipv4_hdr pkt_ipv4_hdr;
    struct rte_udp_hdr pkt_udp_hdr;

    uint32_t seed = 123456;
    uint32_t srcaddr = IPV4_ADDR(192, 168, 2, 106);
    uint32_t dstaddr = IPV4_ADDR(192, 168, 2, 107);
    uint16_t srcport = (uint16_t)rand_r(&seed);
    uint16_t dstport = 9999;
    uint16_t ether_len, ip_len, udp_len;
    uint16_t pktlen;

    static uint8_t srcmac[] = {0x00, 0x0c, 0x29, 0x20, 0x3b, 0xc2};
    static uint8_t dstmac[] = {0x00, 0x0c, 0x29, 0x98, 0x0d, 0xd1};

    uint16_t ether_type = RTE_ETHER_TYPE_IPV4;

    initialize_eth_header(&pkt_eth_hdr, (struct rte_ether_addr*)srcmac,
                          (struct rte_ether_addr*)dstmac, ether_type, 0, 0);
    ether_len = (uint16_t)(sizeof(struct rte_ether_hdr));

    udp_len = initialize_udp_header(&pkt_udp_hdr, srcport, dstport, msglen);

    ip_len = initialize_ipv4_header(&pkt_ipv4_hdr, srcaddr, dstaddr, udp_len);
    pktlen = ether_len + ip_len;

    // return generate_packet_burst(mp, bufs, idx, &pkt_eth_hdr, 0,
    // &pkt_ipv4_hdr,
    //                             1, &pkt_udp_hdr, msg, msglen, 1, pktlen, 1);
    int ret = hanr_generate_packet_burst(mp, bufs, idx, &pkt_eth_hdr, 0,
                                         &pkt_ipv4_hdr, 1, &pkt_udp_hdr, msg,
                                         msglen, 1, pktlen, 1, 0);
    if (ret < 0) {
        printf("generate packet failed.\n");
    }
    return ret;
}

static inline int hanr_client_create_register_request(struct rte_mempool* mp,
                                                      struct rte_mbuf** bufs,
                                                      int idx) {
    uint32_t rid = ++hanr_request_id;
    struct hanr_msg_register_request msg = {0};
    msg.type = HANR_MSG_REGISTER_REQUEST;
    msg.len = htons(sizeof(struct hanr_msg_register_request));
    msg.request_id = htonl(rid);
    msg.timestamp = htonl(time(NULL));
    snprintf(msg.eid, HANR_EID_LEN, "eid-%010d", rid);
    snprintf(msg.na, HANR_NA_LEN, "na-%010d", rid);

    if (hanr_conf.verbose) {
        hanr_dump_register_request(&msg);
    }

    return hanr_client_create_packet(mp, bufs, idx, (uint8_t*)&msg,
                                     sizeof(msg));
}

static inline int hanr_client_create_withdraw_request(struct rte_mempool* mp,
                                                      struct rte_mbuf** bufs,
                                                      int idx) {
    uint32_t rid = ++hanr_request_id;
    struct hanr_msg_withdraw_request msg = {0};
    msg.type = HANR_MSG_WITHDRAW_REQUEST;
    msg.len = htons(sizeof(struct hanr_msg_withdraw_request));
    msg.request_id = htonl(rid);
    msg.timestamp = htonl(time(NULL));
    snprintf(msg.eid, HANR_EID_LEN, "eid-%010d", rid);

    if (hanr_conf.verbose) {
        hanr_dump_withdraw_request(&msg);
    }

    return hanr_client_create_packet(mp, bufs, idx, (uint8_t*)&msg,
                                     sizeof(msg));
}

static inline int hanr_client_create_query_request(struct rte_mempool* mp,
                                                   struct rte_mbuf** bufs,
                                                   int idx) {
    uint32_t rid = ++hanr_request_id;
    //uint32_t rid = 1;
    struct hanr_msg_query_request msg = {0};
    msg.type = HANR_MSG_QUERY_REQUEST;
    msg.prefix = 111;
    msg.len = htons(sizeof(struct hanr_msg_query_request));
    msg.request_id = htonl(rid);
    msg.timestamp = htonl(time(NULL));
    snprintf(msg.eid, HANR_EID_LEN, "eid-%010d", rid);

    if (hanr_conf.verbose) {
        hanr_dump_query_request(&msg);
    }

    return hanr_client_create_packet(mp, bufs, idx, (uint8_t*)&msg,
                                     sizeof(msg));
}

static int hanr_client_create_register_requests(struct rte_mempool* mp,
                                                struct rte_mbuf** bufs,
                                                int burst) {
    int i;
    for (i = 0; i < burst; i++) {
        hanr_client_create_register_request(mp, bufs, i);
    }

    return burst;
}

static int hanr_client_create_withdraw_requests(struct rte_mempool* mp,
                                                struct rte_mbuf** bufs,
                                                int burst) {
    int i;
    for (i = 0; i < burst; i++) {
        hanr_client_create_withdraw_request(mp, bufs, i);
    }

    return burst;
}

static int hanr_client_create_query_requests(struct rte_mempool* mp,
                                             struct rte_mbuf** bufs,
                                             int burst) {
    int i;
    for (i = 0; i < burst; i++) {
        hanr_client_create_query_request(mp, bufs, i);
    }

    return burst;
}

int hanr_client_process_tx(struct hanr_client_conf* conf,
                           struct rte_mbuf** bufs,
                           int burst) {
    int ret = 0;

    switch (conf->msgtype) {
        case HANR_MSG_REGISTER:
            ret = hanr_client_create_register_requests(conf->tx_pool, bufs,
                                                       burst);
            break;
        case HANR_MSG_QUERY:
            ret = hanr_client_create_query_requests(conf->tx_pool, bufs, burst);
            break;
        case HANR_MSG_WITHDRAW:
            ret = hanr_client_create_withdraw_requests(conf->tx_pool, bufs,
                                                       burst);
            break;
        default:
            printf("unknown msgtype: %d\n", conf->msgtype);
    }

    return ret;
}

static struct rte_mbuf* bufs[RTE_MAX_ETHPORTS][MAX_PKT_BURST];
/**
 * @brief TX main
 * @param  arg              My Param doc
 * @return int
 */
int hanr_tx_main(void* arg) {
    printf("Start tx on lcore: %d, socket: %d\n", rte_lcore_id(),
           rte_socket_id());

    int ret;
    int i;
    uint64_t count = 0;
    uint64_t start, end, diff;
    uint64_t pkts = 0, pkts_diff = 0, pkts_last = 0;
    struct hanr_lcore_port_queue* pq = &hanr_conf.txq[rte_lcore_id()];
    struct rte_mbuf** mbuf;
    mbuf = bufs[pq->port_id];
    uint64_t rate_curr;
    uint64_t rate_next = 0;
    rate_curr = rte_rdtsc();
    rte_delay_ms(10000);  // wait 10s for the port to be ready.
    uint32_t burst = MAX_PKT_BURST;
    int to_send = hanr_conf.count;
    uint64_t us = rte_get_timer_hz() / US_PER_S;
    start = rte_rdtsc();
    uint64_t slot = rte_get_timer_hz() / HANR_MAX_RATE;

    while (!hanr_quit) {
        rate_curr = rte_rdtsc();
        if (rate_next > rate_curr) {
            continue;
        }
        rate_next = rate_curr + slot * burst;
        
        if (hanr_conf.count > 0) {
            if (to_send <= 0) {
                hanr_quit = 0;
                end = rte_rdtsc();
                diff = end - start;
                printf("Pkts: %lu, Time: %lu us, Pkts/s: %lu\n", pkts,
                       diff / us,
                       (uint64_t)(pkts / (1.0 * diff / rte_get_timer_hz())));
                return 0;
            }
            burst = to_send > MAX_PKT_BURST ? MAX_PKT_BURST : to_send;
        }

        ret = hanr_client_process_tx(&hanr_conf, mbuf, 1);

        ret = rte_eth_tx_burst(pq->port_id, pq->queue_id, mbuf, ret);
        if (ret <= 0) {
            printf("TX failed.\n");
            continue;
            // return 0;
        }
        if (hanr_conf.count > 0) {
            to_send -= ret;
        }

        rte_delay_ms(30000);

        pkts += ret;
        count++;

        if (count % 100000 == 0) {
            end = rte_rdtsc();
            diff = end - start;
            pkts_diff = pkts - pkts_last;
            pkts_last = pkts;
            printf(
                "[%d:%d:%d] Send Packets: %lu\t : Total: %lu cycles, AVG: %.f "
                "cycles\n",
                rte_lcore_id(), pq->port_id, pq->queue_id, pkts_diff, diff,
                (double)diff / pkts_diff);
            //printf("mempool: size: %u, populated: %u\n",
            //       rte_mempool_avail_count(hanr_conf.tx_pool),
            //       rte_mempool_in_use_count(hanr_conf.tx_pool));
            struct rte_eth_stats stats;
            rte_eth_stats_get(pq->port_id, &stats);
            printf("packets: %lu/%lu, bytes: %lu/%lu, errors: %lu/%lu, imissed: %lu, nombuf: %lu\n",
                stats.ipackets, stats.opackets,
                stats.ibytes, stats.obytes,
                stats.ierrors, stats.oerrors,
                stats.imissed, stats.rx_nombuf);
            start = rte_rdtsc();
        }
        //*/
    }
}
