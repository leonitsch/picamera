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


mbedtls_ecdsa_context ctx;
mbedtls_ctr_drbg_context ctr_drgb;
mbedtls_entropy_context entropy;
char b64pubkey[300];
char b64signature[2048];

/*! \fn int picamera_init()
    \brief Initializes the Entropy, RNG and the ecdsa context
*/
// I
int picamera_init(){
  char *pers = "personal seed";
  mbedtls_ctr_drbg_init(&ctr_drgb);
  mbedtls_entropy_init(&entropy);
  int err = 0;
  if( (err = mbedtls_ctr_drbg_seed(&ctr_drgb,mbedtls_entropy_func, &entropy,(unsigned char*) pers, strlen(pers))) != 0){
    printf("failed!, ctr_drgb_seed returned %d \n", err);
    return err;
  }  
  mbedtls_ecdsa_init(&ctx);
  return err;
}

void picamera_genkey(){
  printf("Generating new ECP Keypair... \n");
  // mbedtls_ecdsa_init(&ctx);
  int err = mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &ctr_drgb);
  char errbuff[1024];
  memset(errbuff,0,1024);
  mbedtls_strerror(err, errbuff, 1024);
  printf( "Key Generation: ok (key size: %d bits)\n", (int) ctx.private_grp.pbits );

  char buf[MBEDTLS_ECP_MAX_PT_LEN];
  memset(buf,0,MBEDTLS_ECP_MAX_PT_LEN);
  size_t olen;
  err = mbedtls_ecp_point_write_binary(&ctx.private_grp, &ctx.private_Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, (unsigned char*) buf, MBEDTLS_ECP_MAX_PT_LEN);
  //printf("output length of ecp write point: %i \nPublic Key hex Representation: \n   ", olen);
  // printf("C Public Key: ");
  // for (int i = 0; i < olen; i++){
  //   printf("%02x", buf[i]);
  // }
  // printf("\n");
  if (err != 0 ){
    printf("Error writing point to binary \n");
  }
  memset(b64pubkey,0,300);
  mbedtls_base64_encode((unsigned char*) b64pubkey, 300, &olen,(unsigned char*) buf, olen);
  printf("Public Key Base 64: %s \n", b64pubkey);
}

char* picamera_get_publickey(){
  printf("C Public Key: %s\n", b64pubkey);
  //strcpy(b64pubkey, "BODYLcWaCn4NQ2T8wqicvC7CDwkcExrtX5rysFw+Hnjja8eH3GCD/79QpwEfaPk+OB3J2FHjy+yX7GIJx9MV/88=");
  return b64pubkey;
  // return "BODYLcWaCn4NQ2T8wqicvC7CDwkcExrtX5rysFw+Hnjja8eH3GCD/79QpwEfaPk+OB3J2FHjy+yX7GIJx9MV/88=";
}

char* picamera_get_signature(char *hash){
  char b64hash[strlen(hash)];
  // Print Hash in Hex Format for debugging purposes
  printf("C Hash no slice: ");
  for (int i = 0; i < strlen(hash); i++){
    printf("%02x", hash[i]);
  }
  printf("\n");
  // Convert and print Hash to base64
  size_t b64_hash_max_size = strlen(hash)*3;
  unsigned char b64_hash[b64_hash_max_size];
  size_t b64_hash_length = 0;
  mbedtls_base64_encode(b64_hash,b64_hash_max_size,&b64_hash_length, hash, strlen(hash));
  printf("Base 64 Hash: %s \n", b64_hash);

  // Create signature
  unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
  unsigned char *hash_unsigned = (unsigned char*) hash;
  size_t slen;
  int err  = mbedtls_ecdsa_write_signature(&ctx,MBEDTLS_MD_SHA256, hash_unsigned, strlen(hash_unsigned), sig, sizeof(sig), &slen, mbedtls_ctr_drbg_random, &ctr_drgb);
  if (err != 0 ){
    printf( " failed\n  ! ecdsa_write_signature returned %d\n", err );
  }
  printf("C Signature:  ");
  for (int i = 0; i < slen; i++){
    printf("%02x", sig[i]);
  }
  printf("\n");

  // encode and print signature to base64
  unsigned int b64len = 0;
  mbedtls_base64_encode((unsigned char *) b64signature, 2048, &b64len, (unsigned char*) sig, slen);
  printf("C Signature:  %s\n",b64signature);
  return b64signature;
}


char* picamera_testpass(char* hash){
  printf("C String print: %s \n", hash);
  return "new String for GO";
}


/*! \fn void picamera_free()
    \brief frees the Entropy, RNG and the ecdsa context
*/
// I
void picamera_free(){
  mbedtls_ecdsa_free(&ctx);
  mbedtls_ctr_drbg_free(&ctr_drgb);
  mbedtls_entropy_free(&entropy);
}