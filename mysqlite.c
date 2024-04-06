//
// Created by root on 3/21/24.
//
#include "utils/log.h"
#include "zlog.h"
#include <cjson/cJSON.h>
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
    int           rc;
    int *id_arr        = (int *) malloc(sizeof(int));
    int id_arr_length = 0;
    // 构建 SQL 语句
    const char *select_sql_template = "SELECT * FROM %Q WHERE uploaded=0 %s";
    char       *select_sql;
    if (threshold <= 0) {
        select_sql = sqlite3_mprintf(select_sql_template, table_name, "");
    } else {
        select_sql =
            sqlite3_mprintf(select_sql_template, table_name, "LIMIT ?");
    }
    rc = sqlite3_prepare_v2(db, select_sql, -1, &select_stmt, NULL);
    if (rc != SQLITE_OK) {
        nlog_error("SQL error: %s\n", sqlite3_errmsg(db));
        sqlite3_free(select_sql);
        return NULL;
    }

    if (threshold > 0) {
        sqlite3_bind_int(select_stmt, 1, threshold);
    }

    // 开始事务
    sqlite3_exec(db, "BEGIN TRANSACTION", 0, 0, 0);
    // 构建 JSON 数组
    cJSON *json_array = cJSON_CreateArray();
    nlog_debug("Start reading records\n");
    while (sqlite3_step(select_stmt) == SQLITE_ROW) {
        id_arr_length++;
        id_arr = (int *) realloc(id_arr, sizeof(int) * id_arr_length);

        cJSON *json_object = cJSON_CreateObject();
        int id = sqlite3_column_int(select_stmt, 0);
        id_arr[id_arr_length - 1] = id;
        cJSON_AddNumberToObject(json_object, "id",id);
        cJSON_AddStringToObject(json_object, "node_name",
                                (char *) sqlite3_column_text(select_stmt, 1));
        cJSON_AddStringToObject(json_object, "group_name",
                                (char *) sqlite3_column_text(select_stmt, 2));
        cJSON_AddNumberToObject(json_object, "timestamp",
                                sqlite3_column_int64(select_stmt, 3));
        cJSON *values = cJSON_Parse((char *) sqlite3_column_text(select_stmt, 4));
        cJSON_AddItemToObject(json_object, "values", values);
        cJSON *errors = cJSON_Parse((char *) sqlite3_column_text(select_stmt, 5));
        cJSON_AddItemToObject(json_object, "errors", errors);
        cJSON *metas = cJSON_Parse((char *) sqlite3_column_text(select_stmt, 6));
        cJSON_AddItemToObject(json_object, "metas", metas);

        cJSON_AddItemToArray(json_array, json_object);
    }
    if(id_arr_length==0) {
        free(id_arr);
        cJSON_Delete(json_array);
        sqlite3_finalize(select_stmt);
        sqlite3_free(select_sql);
        sqlite3_exec(db, "COMMIT TRANSACTION", 0, 0, 0);
        return cJSON_PrintUnformatted(cJSON_CreateArray());
    }
    // 释放资源
    sqlite3_finalize(select_stmt);
    sqlite3_free(select_sql);

    // 计算SQL语句的总长度
    int sql_length = 0;
    for (int i = 0; i < id_arr_length; i++) {
        // 每个ID的最大字符长度为20
        sql_length += 20;
    }
    // 添加额外的长度用于SQL语句的其他部分
    sql_length += 100; // 这里是一个估计值，根据实际情况调整

    // 分配足够大的内存来存储SQL语句
    char *update_sql = (char *) malloc(sql_length * sizeof(char));

    // 构建SQL语句
    char *init_sql =
        sqlite3_mprintf("UPDATE %Q SET uploaded = 1 WHERE id IN (", table_name);
    strcpy(update_sql, init_sql);
    sqlite3_free(init_sql);
    // 在SQL语句中添加ID列表
    for (int i = 0; i < id_arr_length; i++) {
        char id_str[20]; // 假设ID的字符串表示长度不会超过20个字符
        sprintf(id_str, "%d", id_arr[i]);
        strcat(update_sql, id_str);
        if (i < id_arr_length - 1) {
            strcat(update_sql, ", ");
        }
    }

    strcat(update_sql, ")");
    free(id_arr);
    // 执行SQL语句
    char *err_msg = 0;
    rc            = sqlite3_exec(db, update_sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        // 回滚事务
        sqlite3_exec(db, "ROLLBACK TRANSACTION", 0, 0, 0);
        nlog_error("SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        free(update_sql);
        cJSON_Delete(json_array);
        return cJSON_PrintUnformatted(cJSON_CreateArray());
    }

    // 提交事务
    sqlite3_exec(db, "COMMIT TRANSACTION", 0, 0, 0);
    nlog_debug("Records updated successfully\n");
    // 将 cJSON 对象转换为字符串
    char *json_string = cJSON_PrintUnformatted(json_array);
    cJSON_Delete(json_array);
    // 释放动态分配的内存
    free(update_sql);
    return json_string;
}
// 关闭数据库连接
void close_database(sqlite3 *db)
{
    sqlite3_close(db);
}