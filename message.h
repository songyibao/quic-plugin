//
// Created by root on 3/29/24.
//

#ifndef QUIC_MESSAGE_H
#define QUIC_MESSAGE_H

// 消息类型
typedef enum MessageType {
    SUCCESS,
    ERROR,
    SendDataRequest,
    HelloRequest
    // 添加其他类型
} MessageType;

// 状态码
typedef enum StatusCode {
    SEND_DATA = 0,
    HELLO = 1,
    OK = 200,
    BAD_REQUEST = 400,
    UNAUTHORIZED = 401,
    FORBIDDEN = 403,
    NOT_FOUND = 404,
    INTERNAL_SERVER_ERROR = 500,
    // 添加其他状态码
} StatusCode;

// 消息结构体
typedef struct {
    enum MessageType type;
    char *message;
    enum StatusCode status;
    char *data;
} Message;

// 创建消息函数
Message create_message(MessageType type, char *message, StatusCode
                                                                  status, char *data);
// 序列化消息为 JSON 字符串
char *serialize_message(const Message *message);

#endif // QUIC_MESSAGE_H
