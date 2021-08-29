#ifndef _PICAMERA_H
#define _PICAMERA_H


int picamera_init();
char* picamera_testpass(char* hash);
void picamera_genkey();
char* picamera_get_publickey();
char* picamera_get_signature(char* hash);
void picamera_free();

#endif