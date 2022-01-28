#include "hanr_rocksdb.h"
#include <assert.h>
#include <unistd.h>
#include <string.h>

struct hanr_rocksdbinit hanr_rocksdb_init(const char* DBPath){ 
  rocksdb_t *db;
  rocksdb_options_t *options = rocksdb_options_create();
  rocksdb_writeoptions_t *writeoptions = rocksdb_writeoptions_create();
  rocksdb_readoptions_t *readoptions = rocksdb_readoptions_create();
  // Optimize RocksDB. This is the easiest way to
  // get RocksDB to perform well
  long cpus = sysconf(_SC_NPROCESSORS_ONLN);  // get # of online cores
  rocksdb_options_increase_parallelism(options, (int)(cpus));
  rocksdb_options_optimize_level_style_compaction(options, 0);
  // create the DB if it's not already present
  rocksdb_options_set_create_if_missing(options, 1);
  // open DB
  char *err = NULL;
  db = rocksdb_open(options, DBPath, &err);
  assert(!err);
  struct hanr_rocksdbinit dbinit = {db,options,writeoptions,readoptions};
  return dbinit;
}

void hanr_rocksdb_insert(rocksdb_t* db,rocksdb_writeoptions_t *writeoptions,char* key, char* value){
    char* err = NULL;
    rocksdb_put(db, writeoptions, key, strlen(key), value, strlen(value) + 1, &err);
    assert(!err);
}

uint8_t* hanr_rocksdb_get(rocksdb_t* db,rocksdb_readoptions_t *readoptions, char* key) {
  char* err = NULL;
  size_t val_len;
  char* val;
  val = rocksdb_get(db, readoptions, key, strlen(key), &val_len, &err);
  return val;
}

//Update
void hanr_rocksdb_update(rocksdb_t* db, rocksdb_writeoptions_t *writeoptions, rocksdb_readoptions_t *readoptions, char* key, char* newvalue){
    char* err = NULL;
    size_t val_len;
    char* value;
    value = rocksdb_get(db, readoptions, key, strlen(key), &val_len, &err);
    if(newvalue==value)
        return ;
    rocksdb_put(db, writeoptions, key, strlen(key), newvalue, strlen(newvalue) + 1, &err);
    assert(!err);
}


void hanr_rocksdb_delete(rocksdb_t* db, rocksdb_writeoptions_t* writeoptions, char* key){
    char* err = NULL;
    //rocksdb_writeoptions_t *writeoptions = rocksdb_writeoptions_create();
    rocksdb_delete(db, writeoptions, key, strlen(key), &err);
    assert(!err);
}
