//
// Created by root on 3/21/24.
//
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int init_database(sqlite3 **db, char *file)
{
    int rc = sqlite3_open(file, db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(*db));
        sqlite3_close(*db);
    }
    return rc;
}

int table_exists(sqlite3 *db, char *table_name)
{
    sqlite3_stmt *stmt;
    const char   *sql =
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?;";
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    // 绑定参数
    sqlite3_bind_text(stmt, 1, table_name, -1, SQLITE_STATIC);

    // 执行查询
    rc               = sqlite3_step(stmt);
    int table_exists = (rc == SQLITE_ROW);

    // 释放资源
    sqlite3_finalize(stmt);

    return table_exists;
}

// 创建表格
int create_table(sqlite3 *db, const char *table_name)
{
    char *sql = sqlite3_mprintf(
        "CREATE TABLE IF NOT EXISTS %q (id INTEGER PRIMARY KEY "
        "AUTOINCREMENT, node_name TEXT, group_name TEXT, timestamp "
        "INTEGER, data TEXT, errors TEXT, metas TEXT, uploaded INTEGER);",
        table_name);
    int rc = sqlite3_exec(db, sql, 0, 0, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
    }
    return rc;
}

int insert_data(sqlite3 *db, const char *table_name, const char *node_name,
                const char *group_name, long timestamp, const char *values,
                const char *errors, const char *metas)
{
    char *sql = sqlite3_mprintf(
        "INSERT INTO %q (node_name, group_name, timestamp, data, errors, "
        "metas, uploaded) VALUES ('%s', '%s', %ld, '%s', '%s', '%s', '0')",
        table_name, node_name, group_name, timestamp, values, errors, metas);
    fprintf(stderr, "SQL: %s\n", sql);
    int rc = sqlite3_exec(db, sql, 0, 0, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
    }
    sqlite3_free(sql);
    return rc;
}

int check_upload_threshold(sqlite3 *db, int threshold)
{
    sqlite3_stmt *stmt;
    int           count = 0;
    sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM ? WHERE uploaded=0", -1, &stmt,
                       NULL);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count >= threshold;
}
char *read_records(sqlite3 *db, char *table_name, u_int16_t threshold)
{
    sqlite3_stmt *select_stmt;
    sqlite3_stmt *update_stmt;
    int           rc;
    int           update_rc;
    // 开始构建json数组
    int   first_record = 1;
    char *select_sql;
    char *update_sql;

    int *id_arr        = (int *) malloc(sizeof(int));
    int  id_arr_length = 0;

    update_sql =
        sqlite3_mprintf("UPDATE %Q SET uploaded=1 WHERE id=?", table_name);
    if (threshold <= 0) {
        select_sql =
            sqlite3_mprintf("SELECT * FROM %Q WHERE uploaded=0", table_name);
    } else {
        select_sql = sqlite3_mprintf(
            "SELECT * FROM %Q WHERE uploaded=0 LIMIT ?", table_name);
    }
    rc        = sqlite3_prepare_v2(db, select_sql, -1, &select_stmt, NULL);
    update_rc = sqlite3_prepare_v2(db, update_sql, -1, &update_stmt, NULL);
    sqlite3_free(select_sql); // 释放由sqlite3_mprintf分配的内存
    sqlite3_free(update_sql);
    if (rc != SQLITE_OK || update_rc != SQLITE_OK) {
        fprintf(stderr, "SQL: %s\n", select_sql);
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return NULL;
    }
    if (threshold > 0) {
        sqlite3_bind_int(select_stmt, 1, (int) threshold);
    }
    char *json_array = (char *) malloc(sizeof(char) + 1);
    strcpy(json_array, "[");

    while (sqlite3_step(select_stmt) == SQLITE_ROW) {
        id_arr_length++;
        if (!first_record) {
            json_array = realloc(json_array, strlen(json_array) + 2);
            strcat(json_array, ",");
        }
        first_record = 0;
        // 读取每一行数据
        int                  id         = sqlite3_column_int(select_stmt, 0);
        const unsigned char *node_name  = sqlite3_column_text(select_stmt, 1);
        const unsigned char *group_name = sqlite3_column_text(select_stmt, 2);
        long                 timestamp  = sqlite3_column_int64(select_stmt, 3);
        const unsigned char *values     = sqlite3_column_text(select_stmt, 4);
        const unsigned char *errors     = sqlite3_column_text(select_stmt, 5);
        const unsigned char *metas      = sqlite3_column_text(select_stmt, 6);

        id_arr = (int *) realloc(id_arr, sizeof(int) * id_arr_length);
        id_arr[id_arr_length - 1] = id;
        // 构建 JSON 对象字符串并添加到 JSON 数组中
        char *json_object = sqlite3_mprintf(
            "{\"id\": %d, \"node_name\": \"%s\", \"group_name\": \"%s\", "
            "\"timestamp\": %ld, \"values\": %s, \"errors\": %s, \"metas\": "
            "%s}",
            id, node_name, group_name, timestamp, values, errors, metas);
        json_array = realloc(json_array,
                             strlen(json_array) + strlen(json_object) +
                                 2); // Add space for comma and null terminator

        strcat(json_array, json_object);
        sqlite3_free(json_object);
    }
    // 结束 JSON 数组
    json_array = realloc(json_array, strlen(json_array) + 2);
    strcat(json_array, "]");


    // 绑定参数并执行
    for (int i = 0; i < id_arr_length; i++) {
        sqlite3_bind_int(update_stmt, 1, id_arr[i]);
        rc = sqlite3_step(update_stmt);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "更新 ID 为 %d 的记录失败: %s\n", id_arr[i],
                    sqlite3_errmsg(db));
        }
        sqlite3_reset(update_stmt);
    }
    //    // 低效率方法
    //    for(int i =0;i<id_arr_length;i++){
    //        char *sql = sqlite3_mprintf(
    //            "UPDATE %Q SET uploaded=1 WHERE id=%d",
    //            table_name,id_arr[i]);
    //        int rc = sqlite3_exec(db, sql, 0, 0, 0);
    //        if(rc!=SQLITE_OK){
    //            fprintf(stderr,"更新ID为%d的记录时失败\n",id_arr[i]);
    //        }
    //    }
    // 释放资源
    sqlite3_finalize(select_stmt);
    sqlite3_finalize(update_stmt);
    free(id_arr);
    return json_array;
}
// 关闭数据库连接
void close_database(sqlite3 *db)
{
    sqlite3_close(db);
}