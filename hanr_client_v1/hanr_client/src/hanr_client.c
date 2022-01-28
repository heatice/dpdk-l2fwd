#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include "hanr_client.h"
#include "hanr_parse_cmds.h"
#include "hanr_packet_generator.h"


struct hanr_client_conf hanr_conf;
volatile bool hanr_quit = false;

static const struct rte_eth_conf hanr_port_conf_default = {
    .rxmode =
        {
            .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        },
    .txmode =
        {
            .mq_mode = ETH_MQ_TX_NONE,
        },
};


/**
 * @brief Main to start TX/RX routine.
 * @param  opts             My Param doc
 * @return int 
 */
static int hanr_client_main(struct hanr_client_conf *conf)
{
    uint32_t lcore_id;
    struct hanr_lcore_port_queue *p;
    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++)
    {
        // RX
        p = &conf->rxq[lcore_id];
        if (p->lcore_id > 0)
        {
            rte_eal_remote_launch(hanr_rx_main, conf, p->lcore_id);
        }
        // TX   
        p = &conf->txq[lcore_id];
        if (p->lcore_id > 0)
        {
            if (conf->msgtype > 0 && conf->msgtype < HANR_MSG_MAX) {
                rte_eal_remote_launch(hanr_tx_main, conf, p->lcore_id);
            }
        }
    }

    rte_eal_mp_wait_lcore();

    return 0;
}

/**
 * @brief Signal handler for SIGINT & SIGTERM
 * @param  signum           My Param doc
 */
static void hanr_client_signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM)
    {
        printf("Preparing to exit...\n");
        hanr_quit = true;
    }
}



static int hanr_port_init(uint16_t port, struct rte_mempool* mbuf_pool) {
    struct rte_eth_conf port_conf = hanr_port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1; 
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int ret;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    /* Check if port_id of device is attached */
    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    /* Retrieve the contextual information of an Ethernet device. */
    rte_eth_dev_info_get(port, &dev_info);

    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE) {
        port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    }

    /* Configure the Ethernet device. */
    ret = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (ret != 0) {
        return ret;
    }

    /* Check that numbers of Rx and Tx descriptors satisfy descriptors limits
     * from the ethernet device information, otherwise adjust them to
     * boundaries. */
    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (ret != 0) {
        return ret;
    }

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        // Allocate and set up a receive queue for an Ethernet device.
        ret = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                     /* Return the NUMA socket to which an
                                        Ethernet device is connected */
                                     rte_eth_dev_socket_id(port), NULL,
                                     mbuf_pool);
        if (ret < 0) {
            return ret;
        }
        //rte_eth_add_rx_callback(port, q, irs_add_timestamps, NULL);
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        /* Allocate and set up a transmit queue for an Ethernet device. */
        ret = rte_eth_tx_queue_setup(port, q, nb_txd,
                                     rte_eth_dev_socket_id(port), &txconf);
        if (ret < 0) {
            return ret;
        }
        //rte_eth_add_tx_callback(port, q, irs_calc_latency, NULL);
    }

    /* Start the Ethernet port. */
    ret = rte_eth_dev_start(port);
    if (ret < 0) {
        return ret;
    }

    /* Display the port MAC address. */
    struct rte_ether_addr addr;
    rte_eth_macaddr_get(port, &addr);

    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
                 " %02" PRIx8 " %02" PRIx8 "\n",
                 port, addr.addr_bytes[0], addr.addr_bytes[1],
                 addr.addr_bytes[2], addr.addr_bytes[3], addr.addr_bytes[4],
                 addr.addr_bytes[5]);

    /* Enable RX in promiscuous mode for the Ethernet device. */
    rte_eth_promiscuous_enable(port);

    return 0;
}


/**
 * @brief Allocate lcore for RX/TX, Simple case.
 *          - 1 RXQ & 1 RXQ per port
 *          - 1 lcore per RXQ or TXQ
 * @return int 
 */
static int hanr_client_alloc_lcore_for_rxtx()
{
    uint32_t lcore_id;
    uint16_t port_id;
    /*
    lcore_id = rte_get_next_lcore(0, true, false);
    if (lcore_id == RTE_MAX_LCORE) {
        rte_exit(EXIT_FAILURE, "Error: not enough cores.\n");
    }
    */
    lcore_id = rte_get_next_lcore(lcore_id, true, false);
    if (lcore_id == RTE_MAX_LCORE) {
        rte_exit(EXIT_FAILURE, "Error: not enough cores.\n");
    }
    
    RTE_ETH_FOREACH_DEV(port_id) {
        hanr_conf.rxq[lcore_id].lcore_id = lcore_id;
        hanr_conf.rxq[lcore_id].port_id = port_id;
        hanr_conf.rxq[lcore_id].queue_id = 0;  // 1 queue per port
        lcore_id = rte_get_next_lcore(lcore_id, true, false);
        if (lcore_id == RTE_MAX_LCORE) {
            rte_exit(EXIT_FAILURE, "Error: not enough cores.\n");
        }
        // skip 1 lcore to make sure mem & lcore in the same socket.
        lcore_id = rte_get_next_lcore(lcore_id, true, false);
        if (lcore_id == RTE_MAX_LCORE) {
            rte_exit(EXIT_FAILURE, "Error: not enough cores.\n");
        }
        hanr_conf.txq[lcore_id].lcore_id = lcore_id;
        hanr_conf.txq[lcore_id].port_id = port_id;
        hanr_conf.txq[lcore_id].queue_id = 0;  // 1 queue per port
        lcore_id = rte_get_next_lcore(lcore_id, true, false);
        if (lcore_id == RTE_MAX_LCORE) {
            //rte_exit(EXIT_FAILURE, "Error: not enough cores.\n");
            printf("finally not enough cores\n");
        }
    }
}

/**
 * @brief Initialize IRS client
 * @return int 
 */
static int hanr_client_init()
{
    uint16_t nb_ports;
    uint16_t port_id;

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 1) {
        rte_exit(EXIT_FAILURE, "Error: no ports available\n");
    }

    // Alloc memory pool for RX
    hanr_conf.rx_pool = rte_pktmbuf_pool_create("RX_MBUF_POOL", NUM_MBUFS * nb_ports,
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (hanr_conf.rx_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }
    // Alloc memory pool for TX
    hanr_conf.tx_pool = rte_pktmbuf_pool_create("TX_MBUF_POOL", NUM_MBUFS * nb_ports,
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (hanr_conf.tx_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create tx mbuf pool\n");
    }

    // Init port
    RTE_ETH_FOREACH_DEV(port_id) {
        if (hanr_port_init(port_id, hanr_conf.rx_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", port_id);
    }

    return hanr_client_alloc_lcore_for_rxtx();
}



int main(int argc, char *argv[])
{
    int ret;

    // Initialize EAL of DPDK
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        printf("Init EAL failed.\n");
        return 0;
    }

    argc -= ret;
    argv += ret;

    // Register signal handler for SIGINT & SIGTERM
    signal(SIGINT, hanr_client_signal_handler);
    signal(SIGTERM, hanr_client_signal_handler);
    // Parse command line options
    ret = hanr_client_parse_cmds(&hanr_conf, argc, argv);
    if (ret < 0) {
        return 0;
    }

    // Initialize HANR client
    ret = hanr_client_init();
    if (ret < 0) {
        printf("Initialize failed for IRS client.\n");
        return 0;
    }
    // Main Loop of client
    hanr_client_main(&hanr_conf);

    // Cleanup for EAL
    rte_eal_cleanup();

    return 0;
}