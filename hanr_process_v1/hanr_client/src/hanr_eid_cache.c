#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_hash.h>
#include <rte_lcore.h>
#include <rte_errno.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include "hanr_eid_cache.h"


#define HANR_EID_HASH_SIZE 1000


int hanr_eid_cache_init(struct hanr_eid_cache *cache)
{
    int ret;

    struct rte_hash_parameters hash_params = {
		.entries = HANR_EID_HASH_SIZE * 2, /* table load = 50% Total table entries. */
		.key_len = HANR_EID_LEN, /* Store IPv4 dest IP address Length of hash key.  */
		.socket_id = rte_socket_id(),//NUMA Socket ID for memory. 
		.hash_func_init_val = 0,//Init value used by hash_func. 
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,//额外标志 thread safety
	};

    hash_params.name = "ht_hanr_eid";

    //创建hash表，根据上边的hash参数
    cache->ht_eid = rte_hash_create(&hash_params);
    if (cache->ht_eid == NULL) {
        printf("rte_hash_create failed.[%d]%s\n", rte_errno, rte_strerror(rte_errno));
        return -1;
    }

    return 0;
}
//释放cache,删除hash
int hanr_eid_cache_free(struct hanr_eid_cache *cache)
{
    assert(cache != NULL && cache->ht_eid != NULL);
    int ret;
    const void *eid;
    void *na;
    struct hanr_cache_entry *entry;
    void *data;
    uint32_t next, na_next;

    while (rte_hash_iterate(cache->ht_eid, &eid, (void**)&entry, &next) >= 0) {
        
    }
    rte_hash_free(cache->ht_eid);

    return 0;
}

//写一个key=eid，value=na的cache_put
int hanr_eid_cache_put(struct hanr_eid_cache *cache, uint8_t *eid, void *val)
{
    struct hanr_cache_entry *entry;
    int ret;
    //struct hanr_msg_data value;

    ret = rte_hash_lookup_data(cache->ht_eid, eid, (void**)&entry);
    if (ret == -EINVAL) {
        printf("rte_hash_lookup_data failed.\n");
        return ret;
    } else if (ret == -ENOENT) {
        //分配内存
        entry = rte_malloc(NULL,sizeof(struct hanr_cache_entry),0);
        //将val参数赋值给entry—>data
        entry->data = (struct hanr_msg_data *)val;
        //添加
        ret = rte_hash_add_key_data(cache->ht_eid, eid, (void*)entry);
        if (ret != 0) {
            printf("rte_hash_add_key_data failed.\n");
            return -1;
        }
    }

    return 0;
}

//我得自己写一个函数能够根据eid查询na
void* hanr_eid_cache_get_by_eid(struct hanr_eid_cache *cache, uint8_t *eid)
{
    int ret;
    void *val;
    //这里val是一个struct hanr_cache_entry的指针，na=val->data
    ret = rte_hash_lookup_data(cache->ht_eid, eid, (void**)&val);
    if (ret == -EINVAL) {
        printf("rte_hash_lookup_data failed.\n");
        return NULL;
    } else if (ret == -ENOENT) {
        return NULL;
    }

    return val;
}

//写一个删除
int hanr_eid_cache_del(struct hanr_eid_cache *cache, uint8_t *eid)
{
    int ret;

    ret = rte_hash_del_key(cache->ht_eid, eid);
    if (ret < 0)
    {
         printf("del failed.\n");
        return ret;
    }
    
    return ret;
}