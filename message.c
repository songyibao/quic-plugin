//
// Created by root on 3/29/24.
//
#include "message.h"
#include "cjson/cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// 映射枚举类型到字符串
const char* MessageTypeStrings[] = {
    "SUCCESS",
    "ERROR",
    "SendDataRequest",
    "HelloRequest"
    // 添加更多的消息类型对应的字符串...
};
// 创建消息函数
Message create_message(MessageType type, char *message, StatusCode
                                                                  status,
                       char *data) {
    Message new_message;
    new_message.type = type;
    new_message.message = message;
    new_message.status = status;
    new_message.data = data;
    return new_message;
}

// 序列化消息为 JSON 字符串
char *serialize_message(const Message *message) {
    cJSON *root = cJSON_CreateObject();
    // 确保消息类型在有效范围内
    if (message->type >= 0 && message->type < sizeof(MessageTypeStrings) / sizeof(MessageTypeStrings[0])) {
        cJSON_AddStringToObject(root, "type", MessageTypeStrings[message->type]);
    } else {
        cJSON_AddStringToObject(root, "type", "UnknownMessageType");
    }
    char *tmp = (char *)malloc(sizeof(char) * (strlen(message->message)+1));
    strcpy(tmp, message->message);
    cJSON_AddStringToObject(root, "message", tmp);
    cJSON_AddNumberToObject(root, "status", message->status);
    cJSON *dataj = cJSON_Parse(message->data);
    cJSON_AddItemToObject(root,"data",dataj);
    char *json_string = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json_string;
}