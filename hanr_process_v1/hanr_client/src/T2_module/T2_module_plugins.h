#ifndef T2_PLUGINS
#define T2_PLUGINS

#include "../hanr_client.h"

int hanr_t2_do_query(struct hanr_client_conf *cfg,struct hanr_packet *pkt, struct hanr_msg_query_request *query_request);

#endif