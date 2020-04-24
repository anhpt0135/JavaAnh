/*
 * ssl_ext_def.h
 *
 *  Created on: Apr 14, 2020
 *      Author: anhpt
 */

#ifndef SSL_EXT_DEF_H_
#define SSL_EXT_DEF_H_

#include "mbedtls/ssl.h"

struct MemoryStruct
{
    mbedtls_ssl_context *ssl;
    int *result;
};

typedef struct psk_entry
{
    const char          *name;
    size_t              key_len;
    char                key[MBEDTLS_PSK_MAX_LEN];
    struct psk_entry    *next;
} psk_entry_t;

#define MAX_WORKER_THREADS  3
#define BUFFER_MAX_LENGTH   2048

#define mbedtls_free        free
#define mbedtls_time        time
#define mbedtls_time_t      time_t
#define mbedtls_calloc      calloc
#define mbedtls_fprintf     fprintf

int send_command(void);


#endif /* SSL_EXT_DEF_H_ */
