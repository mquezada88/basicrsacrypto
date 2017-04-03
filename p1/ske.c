#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+-------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(C) (32 bytes for SHA256) |
 * +------------+--------------------+-------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen){
	if(entropy != NULL){
		unsigned char* outputBuffer;
		outputBuffer = malloc(64);
		HMAC(EVP_sha512(), KDF_KEY, 32, entropy, entLen, outputBuffer, NULL);
		for (int i = 0; i < 32; i++)
			K->hmacKey[i] = outputBuffer[i];
		for (int i = 32; i < 64; i++)
			K->aesKey[i-32] = outputBuffer[i];
		free(outputBuffer);
	}else{
		unsigned char* buff1; //Buffer for randBytes
		unsigned char* buff2;
		buff1 = malloc(32);
		buff2 = malloc(32);
		randBytes(buff1, 32); //Create random bytes
		randBytes(buff2, 32);
		for (int i = 0; i < 32; i++)
			K->hmacKey[i] = buff1[i];
		for (int i = 0; i < 32; i++)
			K->aesKey[i] = buff2[i];
		/*Free up memory*/
		free(_buff1);
		free(_buff2);
	}
	return 0;
}

size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}

size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K, unsigned char* IV){
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */
	
	if (IV == NULL)
		for (int i = 0; i < 16; i++)
			IV[i] = i;
	memcpy(outBuf, IV, 16);
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, IV)) 
		ERR_print_errors_fp(stderr);
	int nWritten;
	if (1 != EVP_EncryptUpdate(ctx, outBuf + 16, &nWritten, inBuf, len))
		ERR_print_errors_fp(stderr);
	EVP_CIPHER_CTX_free(ctx);
	int total = 16 + 32 + nWritten;
	unsigned char myBuf[nWritten];
	memcpy(myBuf, outBuf+16, nWritten);
	unsigned char* _HMAC = malloc(HM_LEN);
	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, outBuf, nWritten+16, _HMAC, NULL);
	memcpy(outBuf + 16 + nWritten, _HMAC, 32);
	return total;
}

size_t ske_encrypt_file(const char* fnout, const char* fnin, SKE_KEY* K, unsigned char* IV, size_t offset_out){
	if (IV == NULL)
		for (int i = 0; i < 16; i++)
			IV[i] = i;
	int fd = open(fnin, O_RDONLY);
	if (fd == -1)
		return -1; struct stat sb;
	if (fstat(fd, &sb) == -1)
		return -1;
	if (sb.st_size == 0)
		return -1;
	char *src;
	src = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (src == MAP_FAILED)
		return -1;
	size_t len = strlen(src) + 1;
	size_t ctLen = ske_getOutputLen(len);
	unsigned char *ct = malloc(ctLen+1);
	size_t total = ske_encrypt(ct, (unsigned char*)src, len, K, IV);
	int dd = open(fnout, O_CREAT | O_RDWR, S_IRWXU);
	write(dd, ct, (int)total);
	return 0;
}

size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len, SKE_KEY* K) {
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */
	return 0;
}
size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in)
{
	/* TODO: write this. */
	return 0;
}
