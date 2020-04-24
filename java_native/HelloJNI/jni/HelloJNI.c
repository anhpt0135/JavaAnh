/*
 * HelloJNI.c
 *
 *  Created on: Apr 23, 2020
 *      Author: anhpt0135
 */
#include <jni.h>
#include <stdio.h>
#include "HelloJNI.h"
#include "ssl_ext_def.h"
#include <string.h>
#include <unistd.h>
#include "ssl_ext_def.h"
#include "mbedtls/certs.h"
#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/timing.h"
#include "mbedtls/x509.h"

static const char psk_id[] = "Client_identity";
static mbedtls_ssl_config g_conf;
static const char *g_psk = "46A08A57073DB2AA6BD3F69A75EA694D";
static const char *g_psk_identity = "dnh4ch446jgj17v6eqmjc104rj";

static void init_psk(unsigned char *psk, int *psk_len){
	if (strlen(g_psk)) {
	        unsigned char c;
	        size_t j;

	        if (strlen(g_psk) % 2 != 0) {
	            printf("*** pre-shared key not valid hex (1)\n");
	            return;
	        }

	        *psk_len = strlen(g_psk) / 2;

	        for (j = 0; j < strlen(g_psk); j += 2) {
	            c = g_psk[j];
	            if (c >= '0' && c <= '9')
	                c -= '0';
	            else if (c >= 'a' && c <= 'f')
	                c -= 'a' - 10;
	            else if (c >= 'A' && c <= 'F')
	                c -= 'A' - 10;
	            else {
	                printf("*** pre-shared key not valid hex (2)\n");
	                return;
	            }
	            psk[j / 2] = c << 4;

	            c = g_psk[j + 1];
	            if (c >= '0' && c <= '9')
	                c -= '0';
	            else if (c >= 'a' && c <= 'f')
	                c -= 'a' - 10;
	            else if (c >= 'A' && c <= 'F')
	                c -= 'A' - 10;
	            else {
	                printf("pre-shared key not valid hex (3)\n");
	                return;
	            }
	            psk[j / 2] |= c;
	        }
	        int y = 0;
	        for (y = 0; y < sizeof(psk); y++) {
	            printf("*** PSK %02x\n", psk[y]);
	        }
	    }
	else
		printf("g_psk is null\n");
}



static int send_command_hi(char response []) {
	printf("Inside send command function\n");
		const char *pers = "ssl_client";
		char buf[MBEDTLS_SSL_MAX_CONTENT_LEN + 1];
		unsigned char psk[MBEDTLS_PSK_MAX_LEN];
		int psk_len = 0;
		mbedtls_entropy_context entropy;
		mbedtls_ctr_drbg_context ctr_drbg;
		mbedtls_ssl_context ssl;
		int ret = 0;
		char *hostname = "127.0.0.1";
		char *port = "4433";
		const char *command = "action=command&command=get_udid";
		mbedtls_net_context server_ctx;
		mbedtls_net_init(&server_ctx);
		mbedtls_ssl_init(&ssl);
		mbedtls_ssl_config_init(&g_conf);
		mbedtls_ctr_drbg_init(&ctr_drbg);

		mbedtls_entropy_init(&entropy);
		ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
				(const unsigned char*) pers, strlen(pers));
		if (ret != 0) {
			printf("mbedtls_ctr_drbg_seed failed\n");
			return -1;
		}

		if ((ret = mbedtls_net_connect(&server_ctx, hostname, port,
				MBEDTLS_NET_PROTO_TCP)) != 0) {
			printf("mbedtls_net_connect() failed\n");
			return -1;
		}

		printf("Connected....\n");

		if (mbedtls_ssl_config_defaults(&g_conf,
		MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
			printf("mbedtls_ssl_config_default() failed\n");
			return -1;
		}

		mbedtls_ssl_conf_rng(&g_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
		mbedtls_ssl_conf_read_timeout(&g_conf, 5000);
		init_psk(psk, &psk_len);
		if(mbedtls_ssl_conf_psk(&g_conf, psk, psk_len, (unsigned char *)g_psk_identity, strlen(g_psk_identity)) != 0){
			printf("mbedtls_ssl_conf_psk() failed\n");
			return -1;
		}
		printf("mbedtls_ssl_setup()\n");
		if ((ret = mbedtls_ssl_setup(&ssl, &g_conf)) != 0) {
			printf("mbedtls_ssl_setup() failed ret = %d\n", ret);
			return -1;
		}
		//mbedtls_net_set_block(&client_ctx);
		mbedtls_ssl_set_bio(&ssl, &server_ctx, mbedtls_net_send, mbedtls_net_recv,
				NULL);

		if ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
			printf("Failed : mbedtls_ssl_handshake return -0x%x\n", -ret);
			return -1;
		}

		snprintf((char *) buf, sizeof(buf) - 1, "%s\r\n", command);

		int byteSent = 0;
		while (1) {
			ret = mbedtls_ssl_write(&ssl, (const unsigned char *)buf, strlen(buf));
			if (ret <= 0) {
					break;
				}
				byteSent = ret;
			}

		printf("Sent %d bytes\n", byteSent);

		printf("Response from server ... \n");

		memset(buf, 0, sizeof(buf));
		ret = 0;
		while(1){
			ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, sizeof(buf));
			if(ret <= 0){
				break;
			}
		}

		printf("received message: %s\n", buf);
		strncpy(response, buf, strlen(buf) + 1);

		printf("\nClosing socket...\n");

		mbedtls_net_free(&server_ctx);
		mbedtls_ssl_free(&ssl);
		mbedtls_ssl_config_free(&g_conf);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);

		printf("Finished.\n");
		return 0;
}

JNIEXPORT jstring JNICALL Java_HelloJNI_sayHello (JNIEnv *env, jobject jobj, jstring str, jint value){
	printf("Hello from HelloJNI.c\n");
	const char *instr = (*env)->GetStringUTFChars(env,str, NULL);
	char response [128];
	send_command_hi(response);
	printf("received value = %d", (int)value);
	return (*env)->NewStringUTF(env, response);
}
