#ifndef __PROTOCOL_CLASSIFICATION_DEFS_H
#define __PROTOCOL_CLASSIFICATION_DEFS_H

#include <linux/types.h>

// Represents the max buffer size required to classify protocols .
// We need to round it to be multiplication of 16 since we are reading blocks of 16 bytes in read_into_buffer_skb_all_kernels.
// ATM, it is HTTP2_MARKER_SIZE + 8 bytes for padding,
#define CLASSIFICATION_MAX_BUFFER (HTTP2_MARKER_SIZE + 8)

// Checkout https://datatracker.ietf.org/doc/html/rfc7540 under "HTTP/2 Connection Preface" section
#define HTTP2_MARKER_SIZE 24

// The minimal HTTP response has 17 characters: HTTP/1.1 200 OK\r\n
// The minimal HTTP request has 16 characters: GET x HTTP/1.1\r\n
#define HTTP_MIN_SIZE 16

// Postgres

#define POSTGRES_MIN_MSG_SIZE 5
// From https://www.postgresql.org/docs/current/protocol-overview.html:
// The first byte of a message identifies the message type, and the next four bytes specify the length of the rest
// of the message (this length count includes itself, but not the message-type byte). The remaining contents of the
// message are determined by the message type.
// The minimum payloads are for the MOVE/COPY messages which are 4 bytes, so the minimum size is 8 bytes (4 bytes for
// message len, and 4 bytes for the smallest payload).
#define POSTGRES_MIN_PAYLOAD_LEN 8
// Assume typical query message size is below an artificial limit.
// 30000 is copied from postgres code base:
// https://github.com/postgres/postgres/tree/master/src/interfaces/libpq/fe-protocol3.c#L94
#define POSTGRES_MAX_PAYLOAD_LEN 30000
#define POSTGRES_BIND_MAGIC_BYTE 'B'
#define POSTGRES_CLOSE_MAGIC_BYTE 'C'
#define POSTGRES_DESCRIBE_MAGIC_BYTE 'D'
#define POSTGRES_EXECUTE_MAGIC_BYTE 'E'
#define POSTGRES_COPY_FAIL_MAGIC_BYTE 'f'
#define POSTGRES_FLUSH_MAGIC_BYTE 'H'
#define POSTGRES_PARSE_MAGIC_BYTE 'P'
#define POSTGRES_PASSWORD_MESSAGE_MAGIC_BYTE 'p'
#define POSTGRES_QUERY_MAGIC_BYTE 'Q'
#define POSTGRES_SYNC_MAGIC_BYTE 'S'
#define POSTGRES_TERMINATE_MAGIC_BYTE 'X'

// The enum below represents all different protocols we know to classify.
// We set the size of the enum to be 8 bits, by adding max value (max uint8 which is 255) and
// `__attribute__ ((packed))` to tell the compiler to use as minimum bits as needed. Due to our max
// value we will use 8 bits for the enum.
typedef enum {
    PROTOCOL_UNCLASSIFIED = 0,
    PROTOCOL_UNKNOWN,
    PROTOCOL_HTTP,
    PROTOCOL_HTTP2,
    PROTOCOL_TLS,
    PROTOCOL_KAFKA,
    PROTOCOL_MONGO,
    PROTOCOL_POSTGRES,
    //  Add new protocols before that line.
    MAX_PROTOCOLS,
    __MAX_UINT8 = 255,
} __attribute__ ((packed)) protocol_t;

#endif
