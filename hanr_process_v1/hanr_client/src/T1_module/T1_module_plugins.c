#include <stdio.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_lcore.h>

#include "../hanr_rocksdb.h"
#include "../hanr_eid_cache.h"
#include "../hanr_packet_generator.h"
#include "../hanr_msg.h"
#include "T1_module_plugins.h"

static int hash_eid_to_find_t1(uint8_t * query_eid){
    char n_eid[10];
    rte_memcpy(n_eid,query_eid+4,10);
    int val = atoi(n_eid);

    if( val%2==0 ){
        //T1 NA
        return 0;
    }else
    {
        //T1 NA
        return 1;
    }
    
}

static struct rte_mbuf* bufs[RTE_MAX_ETHPORTS][MAX_PKT_BURST];


static inline int hanr_query_create_packet(struct rte_mempool* mp,
                                            struct rte_mbuf** bufs,
                                            struct hanr_packet *pkt,
                                            int idx,
                                            uint8_t* msg,
                                            uint16_t msglen,
                                            uint8_t get) {
    struct rte_ether_hdr pkt_eth_hdr;
    struct rte_ipv4_hdr pkt_ipv4_hdr;
    struct rte_udp_hdr pkt_udp_hdr;

    uint32_t seed = 123456;
    uint32_t srcaddr = IPV4_ADDR(192, 168, 2, 104);
    uint32_t dstaddr = IPV4_ADDR(192, 168, 2, 105);
    uint16_t srcport = (uint16_t)rand_r(&seed);
    uint16_t dstport = 9999;
    uint16_t ether_len, ip_len, udp_len;
    uint16_t pktlen;

    static uint8_t srcmac[] = {0x00, 0x0c, 0x29, 0x98, 0x0d, 0xd1};
    static uint8_t dstmac[] = {0x00, 0x0c, 0x29, 0x20, 0x3b, 0xc2};

    if(get){
        printf("return to client\n");
        for (int i = 0; i < 6; i++)
        {
            srcmac[i] = pkt->eth_hdr->d_addr.addr_bytes[i];
            dstmac[i] = pkt->eth_hdr->s_addr.addr_bytes[i];
        }
        
    }
    
    uint16_t ether_type = RTE_ETHER_TYPE_IPV4;

    initialize_eth_header(&pkt_eth_hdr, (struct rte_ether_addr*)srcmac,
                          (struct rte_ether_addr*)dstmac, ether_type, 0, 0);
    ether_len = (uint16_t)(sizeof(struct rte_ether_hdr));

    udp_len = initialize_udp_header(&pkt_udp_hdr, srcport, dstport, msglen);

    ip_len = initialize_ipv4_header(&pkt_ipv4_hdr, srcaddr, dstaddr, udp_len);

    pktlen = ether_len + ip_len;

    free(pkt);

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


static int hanr_generate_query_mbuf(struct hanr_client_conf *cfg, struct hanr_packet *pkt, uint8_t *msg, uint8_t get){

	printf("start make mbuf.\n");
    int ret = 0;
    struct rte_mbuf **pkts_burst;
    struct hanr_lcore_port_queue* pq = &cfg->rxq[rte_lcore_id()];
    printf("Tx on the lcore: %d; port_id: %d; queue_id: %d\n", pq->lcore_id, pq->port_id, pq->queue_id);

    pkts_burst = bufs[pq->port_id];

    printf("start create packet.\n");
    if(get){
        ret = hanr_query_create_packet(cfg->tx_pool, pkts_burst, pkt, 0, (uint8_t*)msg, sizeof(struct hanr_msg_query_reply), get);
    }else
    {
        ret = hanr_query_create_packet(cfg->tx_pool, pkts_burst, pkt, 0, (uint8_t*)msg, sizeof(struct hanr_msg_query_request), get);
    }
    
    printf("start eth_tx_burst.\n");
    ret = rte_eth_tx_burst(pq->port_id, pq->queue_id, pkts_burst, 1);
    if (ret <= 0) {
        printf("T1 TX failed.\n");
    }
    printf("T1 TX success.\n");
	return ret;

}

int hanr_t1_do_query(struct hanr_client_conf *cfg,struct hanr_packet *pkt, struct hanr_msg_query_request *query_request){
    int ret = 0; 
    printf("t1 process query packets\n");
    uint8_t ipv4 = 1;
    struct hanr_msg_query_reply query_reply = {0}; 
    rte_memcpy(query_reply.eid,query_request->eid,HANR_EID_LEN);

    //put a na in cache to test cache_query temporarily
    uint8_t na[HANR_NA_LEN];
    char *tmp_na = "1234567891234567";
    rte_memcpy(na,tmp_na,HANR_NA_LEN);
    ret = hanr_eid_cache_put(&cfg->eid_cache,query_request->eid,na);
    if(ret!=0){
        printf("add to cache failed\n");
        return -1;
    }
    struct hanr_cache_entry * entry = hanr_eid_cache_get_by_eid(&cfg->eid_cache,query_request->eid);
    if(entry!=NULL){
        printf("lookup in cache:%s\n",entry->data->na);
        //encode cache_query_reply
        query_reply.type = HANR_MSG_QUERY_REPLY;
        query_reply.status = 1;
        query_reply.len = htons(sizeof(struct hanr_msg_query_reply));
        query_reply.request_id = query_request->request_id;
        query_reply.timestamp = htonl(time(NULL));
        rte_memcpy(query_reply.na,entry->data->na,HANR_NA_LEN);

        if (cfg->verbose) {
            hanr_dump_query_reply(&query_reply);
        }
        //reply to client or T0
        ret = hanr_generate_query_mbuf(cfg, pkt, (uint8_t*)&query_reply, 1);
        
        if (ret <= 0) {
            printf("T1 reply TX failed.\n");
            return 0;
        }

    }else
    {
        if(query_request->prefix == PREFIX){

            int deter_t1 = hash_eid_to_find_t1(query_request->eid);
            printf("is self_prefix and deter na :%d\n",deter_t1);

            if(deter_t1){
                //4
                //go to find in db
                //hanr_rocksdb_insert(cfg->database.db,cfg->database.writeoptions,query_request->eid,na);
                char * db_result = hanr_rocksdb_get(cfg->database.db,cfg->database.readoptions,query_request->eid);
                if (db_result!=NULL)
                {
                    printf("lookup in db data:%s\n",db_result);
                    ret = hanr_eid_cache_put(&cfg->eid_cache,query_request->eid,db_result);
                    if(ret!=0){
                        printf("lookup in db but add to cache failed\n");
                    }
                    query_reply.type = HANR_MSG_QUERY_REPLY;
                    query_reply.status = 1;
                    query_reply.len = htons(sizeof(struct hanr_msg_query_reply));
                    query_reply.request_id = query_request->request_id;
                    query_reply.timestamp = htonl(time(NULL));
                    rte_memcpy(query_reply.na,(char *)db_result,HANR_NA_LEN);

                    if (cfg->verbose) {
                        hanr_dump_query_reply(&query_reply);
                    }

                    ret = hanr_generate_query_mbuf(cfg, pkt, (uint8_t*)&query_reply, 1);
                    
                    if (ret <= 0) {
                        printf("T1 reply TX failed.\n");
                        return 0;
                    }

                }else
                {
                    //1
                    printf("can't lookup data in cache and db and reply null.\n");
                    query_reply.type = HANR_MSG_QUERY_REPLY;
                    query_reply.status = 0;
                    query_reply.len = htons(sizeof(struct hanr_msg_query_reply));
                    query_reply.request_id = query_request->request_id;
                    query_reply.timestamp = htonl(time(NULL));
                    char *no_result = "";
                    rte_memcpy(query_reply.na,no_result,HANR_NA_LEN);

                    if (cfg->verbose) {
                        hanr_dump_query_request(query_request);
                    }

                    ret = hanr_generate_query_mbuf(cfg, pkt, (uint8_t*)&query_reply, 1);
                    
                    if (ret <= 0) {
                        printf("T1 reply TX failed.\n");
                        return 0;
                    }

                }

            }else
            {   
                //2
                printf("fwd to other T1.\n");
                if (cfg->verbose) {
                    hanr_dump_query_request(query_request);
                }

                ret = hanr_generate_query_mbuf(cfg, pkt, (uint8_t*)query_request, 0);
                
                if (ret <= 0) {
                    printf("T1 fwd TX failed.\n");
                    return 0;
                }
            }

        }else
        {
            //3
            printf("fwd to higer level T0.\n");
                if (cfg->verbose) {
                    hanr_dump_query_request(query_request);
                }

                ret = hanr_generate_query_mbuf(cfg, pkt, (uint8_t*)query_request, 0);
                
                if (ret <= 0) {
                    printf("T1 fwd TX failed.\n");
                    return 0;
                }

        }
    }

    return ret;
}