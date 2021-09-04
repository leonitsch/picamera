#ifndef _PICAMERA_H
#define _PICAMERA_H


int picamera_init();
char* picamera_testpass(char* hash);
int picamera_genkey(char* pub_key, int pub_key_length);
int picamera_get_signature(char* hash, char* signature);
void picamera_free();

#endif