#ifndef HANR_EID_NA_CACHE_H
#define HANR_EID_NA_CACHE_H

#include <assert.h>
#include <rte_hash.h>

#include "hanr_msg.h"
#include "hanr_client.h"

struct hanr_cache_entry {
    struct hanr_msg_data * data; //data 存na
};

int hanr_eid_cache_init(struct hanr_eid_cache *cache);
int hanr_eid_cache_free(struct hanr_eid_cache *cache);

//hanr new add
int hanr_eid_cache_put(struct hanr_eid_cache *cache, uint8_t *eid, void * val);
void* hanr_eid_cache_get_by_eid(struct hanr_eid_cache *cache, uint8_t *eid);
int hanr_eid_cache_del(struct hanr_eid_cache *cache, uint8_t *eid);


#endif