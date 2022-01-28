#ifndef T1_PLUGINS
#define T1_PLUGINS

#include "../hanr_client.h"

int hanr_t1_do_query(struct hanr_client_conf *cfg,struct hanr_packet *pkt, struct hanr_msg_query_request *query_request);

#endif