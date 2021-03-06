/*
 * HelloJNI.c
 *
 *  Created on: Apr 23, 2020
 *      Author: anhpt0135
 */
#include <jni.h>
#include <stdio.h>
#include "HelloJNI.h"

JNIEXPORT jstring JNICALL Java_HelloJNI_sayHello (JNIEnv *env, jobject jobj, jstring str, jint value){
	printf("Hello from HelloJNI.c\n");
	/*convert the JNI string str into C-string (char *)*/
	const char *instr = (*env)->GetStringUTFChars(env,str, NULL);
	char response[128];
	snprintf(response, 128, "Response the message : %s", instr);
	printf("received value = %d", (int)value);
	return (*env)->NewStringUTF(env, response);
}
