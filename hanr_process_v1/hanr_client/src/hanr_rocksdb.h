#ifndef __HANR_ROCKSDB__
#define __HANR_ROCKSDB__
#include "rocksdb/c.h"
struct hanr_store_msg {
    char * key;
    char * value;//目前假设只有NA信息
};

struct hanr_rocksdbinit
{
    rocksdb_t *db;
    rocksdb_options_t *options ;
    rocksdb_writeoptions_t *writeoptions;
    rocksdb_readoptions_t *readoptions;
};

struct hanr_rocksdbinit hanr_rocksdb_init(const char* DBPath);
void hanr_rocksdb_insert(rocksdb_t* db,rocksdb_writeoptions_t *writeoptions,char* key, char* value);
void hanr_rocksdb_update(rocksdb_t* db, rocksdb_writeoptions_t *writeoptions, rocksdb_readoptions_t *readoptions, char* key, char* newvalue);
uint8_t* hanr_rocksdb_get(rocksdb_t* db,rocksdb_readoptions_t *readoptions, char* key);
void hanr_rocksdb_delete(rocksdb_t* db, rocksdb_writeoptions_t* writeoptions, char* key);
#endif