#include "picamera.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <stddef.h>
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/debug.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/bignum.h"
#include "mbedtls/pk.h"
#include "mbedtls/base64.h"
#include "mbedtls/error.h"
#include "wiringPi.h"
#include <time.h>

mbedtls_ecdsa_context ctx_ecdsa;
mbedtls_ctr_drbg_context ctx_drgb;
mbedtls_entropy_context ctx_entropy;

int picamera_init(){
  wiringPiSetup();
  pinMode(0, INPUT);

  // Setting up the interrupt handler
  wiringPiISR(0, INT_EDGE_RISING, picamera_free);

  // Personal seed for the random number generator
  // Note: this personalization string is not a critical security parameter, entropy will be provided trough a entropy collector
  //       see https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf , Section 8.7.1 for more infos on the personalization string
  char *seed = "picamera";
  mbedtls_ctr_drbg_init(&ctx_drgb);
  mbedtls_entropy_init(&ctx_entropy);
  int err = 0;
  if ( (err = mbedtls_ctr_drbg_seed(&ctx_drgb,mbedtls_entropy_func, &ctx_entropy,(unsigned char*) seed, strlen(seed))) != 0){
    return err;
  }  
  mbedtls_ecdsa_init(&ctx_ecdsa);
  return err;
}


// Function that generates a new ECDSA keypair
int picamera_genkey(char* pub_key, int pub_key_length){
  int err = 0; 
  if ( (err = mbedtls_ecdsa_genkey(&ctx_ecdsa, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &ctx_drgb)) != 0){
    return err;
  }

  printf( "Key Generation: ok (key size: %d bits)\n", (int) ctx_ecdsa.private_grp.pbits );

  char buf[MBEDTLS_ECP_MAX_PT_LEN];
  memset(buf,0,MBEDTLS_ECP_MAX_PT_LEN);
  size_t olen;
  
  if ( (err = mbedtls_ecp_point_write_binary(&ctx_ecdsa.private_grp, &ctx_ecdsa.private_Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, (unsigned char*) buf, MBEDTLS_ECP_MAX_PT_LEN)) != 0 ){
    return err;
  }
  if ( (err = mbedtls_base64_encode((unsigned char*) pub_key, pub_key_length, &olen,(unsigned char*) buf, olen)) != 0){
    return err;
  }
  return 0;
}

// Function that returns a signature for a passed hash
int picamera_get_signature(char *hash, char* signature){
  unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
  unsigned char *hash_unsigned = (unsigned char*) hash;
  size_t slen;
  int err  = 0;
  if ( (err = mbedtls_ecdsa_write_signature(&ctx_ecdsa,MBEDTLS_MD_SHA256, hash_unsigned, strlen(hash_unsigned), sig, sizeof(sig), &slen, mbedtls_ctr_drbg_random, &ctx_drgb)) != 0 ){
    return err;
  }
  unsigned int b64len = 0;
  if ( (err = mbedtls_base64_encode((unsigned char *) signature, 2048, &b64len, (unsigned char*) sig, slen)) != 0) {
    return err;
  }
  return 0;
}


void picamera_free(){
  // Code for measurements of the context free method is in comments: 

  // clock_t start, end;
  // double cpu_time_used;
  // start = clock();
  mbedtls_ecdsa_free(&ctx_ecdsa);
  mbedtls_ctr_drbg_free(&ctx_drgb);
  mbedtls_entropy_free(&ctx_entropy);   
  // end = clock();
  // cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
  // printf("cpu_time needed for context free: %f \n",cpu_time_used);
  exit(0);
}