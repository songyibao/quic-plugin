//
// Created by root on 3/21/24.
//

#ifndef NEURON_MYSQLITE_H
#define NEURON_MYSQLITE_H
#include "sqlite3.h"
int init_database(sqlite3 **db, char *file);

int table_exists(sqlite3 *db, char *table_name);

// 创建表格
int create_table(sqlite3 *db, const char *table_name);

int insert_data(sqlite3 *db, const char *table_name, const char *node_name,
                 const char *group_name, long timestamp, const char *values,
                 const char *errors, const char *metas);
int check_upload_threshold(sqlite3 *db, int threshold);
char *read_records(sqlite3 *db, char *table_name,uint16_t threshold);
// 关闭数据库连接
void close_database(sqlite3 *db);
#endif // NEURON_MYSQLITE_H
