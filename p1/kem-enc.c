/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <gmp.h>

#include "ske.h"
#include "rsa.h"
#include "prf.h"

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Encrypt or decrypt data.\n\n"
"   -i,--in     FILE   read input from FILE.\n"
"   -o,--out    FILE   write output to FILE.\n"
"   -k,--key    FILE   the key.\n"
"   -r,--rand   FILE   use FILE to seed RNG (defaults to /dev/urandom).\n"
"   -e,--enc           encrypt (this is the default action).\n"
"   -d,--dec           decrypt.\n"
"   -g,--gen    FILE   generate new key and write to FILE{,.pub}\n"
"   -b,--BITS   NBITS  length of new key (NOTE: this corresponds to the\n"
"                      RSA key; the symmetric key will always be 256 bits).\n"
"                      Defaults to %lu.\n"
"   --help             show this message and exit.\n";

#define FNLEN 255

enum modes {
	ENC,
	DEC,
	GEN
};

/* Let SK denote the symmetric key.  Then to format ciphertext, we
 * simply concatenate:
 * +------------+----------------+
 * | RSA-KEM(X) | SKE ciphertext |
 * +------------+----------------+
 * NOTE: reading such a file is only useful if you have the key,
 * and from the key you can infer the length of the RSA ciphertext.
 * We'll construct our KEM as KEM(X) := RSA(X)|H(X), and define the
 * key to be SK = KDF(X).  Naturally H and KDF need to be "orthogonal",
 * so we will use different hash functions:  H := SHA256, while
 * KDF := HMAC-SHA512, where the key to the hmac is defined in ske.c
 * (see KDF_KEY).
 * */

#define HASHLEN 32 /* for sha256 */

 // change this KDF_Key by 1 char
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"

int kem_encrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: encapsulate random symmetric key (SK) using RSA and SHA256;
	 * encrypt fnIn with SK; concatenate encapsulation and cihpertext;
	 * write to fnOut. */

	/* +------------+----------------+
	 * | RSA-KEM(X) = RSA(X)|H(X) | SKE ciphertext |
	 * +------------+----------------+ */

	// printf("ENCRYPTING MODE --- ENCRYPTING MODE --- ENCRYPTING MODE --- ENCRYPTING MODE\n");
	// printf("ENCRYPTING MODE --- ENCRYPTING MODE --- ENCRYPTING MODE --- ENCRYPTING MODE\n");
	// printf("ENCRYPTING MODE --- ENCRYPTING MODE --- ENCRYPTING MODE --- ENCRYPTING MODE\n");

	// Step 1: create random bytes.
	// -------------------------------- 
    // generate RSA ciphertext of Random stuff.
    size_t _mLen = rsa_numBytesN(K);
    // printf("%zu - ", _mLen);
    unsigned char* pt = malloc(_mLen);
    unsigned char* ct = malloc(_mLen);
    randBytes(pt, _mLen-1);

    // printf("\nplaintext\n");
    // for (int i = 0; i < _mLen; i++)
    // 	printf("%u ", pt[i]);
    // printf("\n");

    // Step 2: encrypt the random bytes.
    // ------------------------------------
    size_t _ctLen; 
    _ctLen = rsa_encrypt(ct, pt, _mLen, K);

    // printf("\nciphertext of the plaintext\n");
    // for (int i = 0; i < _ctLen; i++)
    // 	printf("%u ", ct[i]);
    // printf("\n");

    // unsigned char* RandDecryp = malloc(_ctLen);
    // rsa_decrypt(RandDecryp, ct, _ctLen, K);

    // for (int i = 0; i < 10; i++)
    // 	printf("%u ", RandDecryp[i]);
    
    // entropy as much as the key using KDF_KEY

    // Step 3: create an HMAC from the original random bytes.
    // ---------------------------------------------------------
    unsigned char* HMACBuf;
	HMACBuf = malloc(64);
	HMAC(EVP_sha512(), KDF_KEY, 32, pt, _mLen, HMACBuf, NULL);

	// printf("\nHMAC part\n");
	// for (int i = 0; i < 64; i++)
	// 	printf("%u ", HMACBuf[i]);
	// printf("\n");

    // Step 4: create SKE_KEY using the original random bytes.
    // ----------------------------------------------------------
	// generate SKE cipher text to append to the back of the final cipher text

	SKE_KEY _K;

	for (int i = 0; i < 32; i++)
		_K.hmacKey[i] = pt[i];

	for (int i = 32; i < 64; i++)
		_K.aesKey[i-32] = pt[i];

	// Step 5: get the text from the input file.
	// ---------------------------------------------
	// open file
	int fd = open(fnIn, O_RDONLY);
    if (fd == -1) return -1;
    struct stat sb;
    if (fstat(fd, &sb) == -1) return -1;
    if (sb.st_size == 0) return -1;

    // put the text in file to buffer fileText
    char* Text;
    Text = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    // Step 6: encrypt the text using SKE and the SKE_KEY built using the random bytes
    // -----------------------------------------------------------------------------------
    unsigned char* IV = malloc(16);
    for (int i = 0; i < 16; i++) IV[i] = i;
    size_t len = strlen(Text) + 1;
    size_t ctLen = ske_getOutputLen(len);
    unsigned char *SKE_ciphertext = malloc(ctLen+1);
    size_t total = ske_encrypt(SKE_ciphertext, (unsigned char*)Text, len, &_K, IV);

    // printf("\nSKE ciphertext\n");
    // for (int i = 0; i < total; ++i)
    // 	printf("%u ", SKE_ciphertext[i]);
    // printf("\n");

    // Step 7: concate encrypt RANDbytes, HMAC(RANDBytes), + the SKEencrypt(RANDBytes)
    // -----------------------------------------------------------------------------------
   	unsigned char * final = malloc(_ctLen+64+total);
    memcpy(final, ct, _ctLen);
    memcpy(final+_ctLen, HMACBuf, 64);
    memcpy(final+_ctLen+64, SKE_ciphertext, total);

    // for (int i = 0; i < _ctLen+64+total; i++)
    // 	printf("%u ", final[i]);

	int out_file = open(fnOut, O_CREAT | O_RDWR, S_IRWXU);
	write(out_file, final, (_ctLen+64+total));

    // printf("\n");

    // printf("total length of the CP %lu\n", _ctLen+64+total);

	return 0;
}

/* NOTE: make sure you check the decapsulation is valid before continuing */
int kem_decrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: write this. */
	/* step 1: recover the symmetric key */
	/* step 2: check decapsulation */
	/* step 3: derive key from ephemKey and decrypt data. */

	// printf("DECRYPTION MODE --- DECRYPTION MODE --- DECRYPTION MODE --- DECRYPTION MODE\n");
	// printf("DECRYPTION MODE --- DECRYPTION MODE --- DECRYPTION MODE --- DECRYPTION MODE\n");
	// printf("DECRYPTION MODE --- DECRYPTION MODE --- DECRYPTION MODE --- DECRYPTION MODE\n");

	// STEP 1: Get the text out of the file
	// --------------------------------------
    int fd = open(fnIn, O_RDONLY);
    if (fd == -1) return -1;
    struct stat sb;
    if (fstat(fd, &sb) == -1) return -1;
    if (sb.st_size == 0) return -1;

    // put the text in file to buffer fileText
    unsigned char* Text;
    Text = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    // printf("\n complete ciphertext \n");
    // for (int i = 0; i < sb.st_size; i++)
    // 	printf("%u ", Text[i]);
    // printf("\n");

    size_t _mLen = rsa_numBytesN(K);
    unsigned char* RandEncryp = malloc(_mLen);
    memcpy(RandEncryp, Text, _mLen);

    // printf("\n random's ciphertext \n");
    // for (int i = 0; i < _mLen; i++)
    // 	printf("%u ", RandEncryp[i]);
    // printf("\n");

    unsigned char* RandDecryp = malloc(_mLen);
    rsa_decrypt(RandDecryp, RandEncryp, _mLen, K);

    // printf("\n plaintext \n");
    // for (int i = 0; i < _mLen; i++)
    // 	printf("%u ", RandDecryp[i]);
    // printf("\n");

    unsigned char* HMACBuf;
	HMACBuf = malloc(64);
	HMAC(EVP_sha512(), KDF_KEY, 32, RandDecryp, _mLen, HMACBuf, NULL);

	// printf("\nHMAC part\n");
	// for (int i = 0; i < 64; i++)
	// 	printf("%u ", HMACBuf[i]);
	// printf("\n");

    unsigned char* symKey = malloc(64);
    memcpy(symKey, Text+_mLen, 64);

	for (int i = 0; i < 64; i++)
	{
		if (symKey[i] != HMACBuf[i])
		{
			printf("FAILEd\n");
			return -1;
		}
	}

   	SKE_KEY _K;

	for (int i = 0; i < 32; i++)
		_K.hmacKey[i] = RandDecryp[i];

	for (int i = 32; i < 64; i++)
		_K.aesKey[i-32] = RandDecryp[i];

	size_t SKE_cp_size = sb.st_size - 64 - _mLen;
	unsigned char* SKE_ciphertext = malloc(SKE_cp_size);
    memcpy(SKE_ciphertext, Text+_mLen+64, SKE_cp_size);

 //    printf("\nSKE ciphertext\n");
	// for (int i = 0; i < SKE_cp_size; i++)
	// 	printf("%u ", SKE_ciphertext[i]);
	// printf("\n");

	unsigned char* pt = malloc(SKE_cp_size);
	size_t r = ske_decrypt(pt, SKE_ciphertext, SKE_cp_size, &_K);

	// printf("\nplaintext\n");
	// for (int i = 0; i < SKE_cp_size; i++)
	// 	printf("%c", pt[i]);
	// printf("\n");

	FILE *f = fopen(fnOut, "w");
    fprintf(f, "%s", pt);
    fclose(f);

	// printf("WORKED\n");

	return 0;
}

int main(int argc, char *argv[]) 
{
	setbuf(stdout, NULL);
	/* define long options */
	static struct option long_opts[] = 
	{
		{"in",      required_argument, 0, 'i'},
		{"out",     required_argument, 0, 'o'},
		{"key",     required_argument, 0, 'k'},
		{"rand",    required_argument, 0, 'r'},
		{"gen",     required_argument, 0, 'g'},
		{"bits",    required_argument, 0, 'b'},
		{"enc",     no_argument,       0, 'e'},
		{"dec",     no_argument,       0, 'd'},
		{"help",    no_argument,       0, 'h'},
		{0,0,0,0}
	};
	/* process options: */
	char c;
	int opt_index = 0;
	char fnRnd[FNLEN+1] = "/dev/urandom";
	fnRnd[FNLEN] = 0;
	char fnIn[FNLEN+1];
	char fnOut[FNLEN+1];
	char fnKey[FNLEN+1];
	memset(fnIn,0,FNLEN+1);
	memset(fnOut,0,FNLEN+1);
	memset(fnKey,0,FNLEN+1);
	int mode = ENC;
	// size_t nBits = 2048;
	size_t nBits = 1024;
	while ((c = getopt_long(argc, argv, "edhi:o:k:r:g:b:", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'h':
				printf(usage,argv[0],nBits);
				return 0;
			case 'i':
				strncpy(fnIn,optarg,FNLEN);
				break;
			case 'o':
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'k':
				strncpy(fnKey,optarg,FNLEN);
				break;
			case 'r':
				strncpy(fnRnd,optarg,FNLEN);
				break;
			case 'e':
				mode = ENC;
				break;
			case 'd':
				mode = DEC;
				break;
			case 'g':
				mode = GEN;
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'b':
				nBits = atol(optarg);
				break;
			case '?':
				printf(usage,argv[0],nBits);
				return 1;
		}
	}
	// printf("Generating a %zu bit key\n", nBits);
	/* TODO: finish this off.  Be sure to erase sensitive data
	 * like private keys when you're done with them (see the
	 * rsa_shredKey function). */
	RSA_KEY K;
	rsa_initKey(&K);
	FILE* f_Public;
	FILE* f_Private;
	char* f_pub = malloc(FNLEN+1);    // 6bitname.pub
	char* f_prvt = malloc(FNLEN+1);   // 5bitname.prvt
	switch (mode) 
	{
		// Encrypt file with the public key and write ciphertext:
		case ENC:
			// printf("Encrypting Data\n");
			// TODO: check if file exists
			strcpy(f_pub, fnKey);
			strcat(f_pub, ".pub");

			// printf("f: %s\n", f_pub);

			f_Public = fopen(f_pub, "r");
			rsa_readPublic(f_Public, &K);		/* set n, e */

			// gmp_printf("---------------------------------------------------\n");
			// gmp_printf("RSA Key Generation\n");
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("p\n------------------------------------------------\n%Zd\n", K.p);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("q\n------------------------------------------------\n%Zd\n", K.q);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("n\n------------------------------------------------\n%Zd\n", K.n);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("e\n------------------------------------------------\n%Zd\n", K.e);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("d\n------------------------------------------------\n%Zd\n", K.d);
			// gmp_printf("---------------------------------------------------\n");
			kem_encrypt(fnOut, fnIn, &K);

			break;

		// Decrypt ct with the private key and write plaintext:
		case DEC:
			// printf("Decrypting Data\n");
			// printf("%s \n", fnKey);

			strcpy(f_pub, fnKey);
			strcat(f_pub, ".pub");
			
			strcpy(f_prvt, fnKey);
			strcat(f_prvt, ".prvt");

			// printf("%s \n", f_pub);
			// printf("%s \n", f_prvt);
			// printf("NEW\n");

			f_Public = fopen(f_pub, "r");
			rsa_readPublic(f_Public, &K);
			fclose(f_Public);

			f_Private = fopen(f_prvt, "r");
			rsa_readPrivate(f_Private, &K);
			fclose(f_Private);

			// gmp_printf("---------------------------------------------------\n");
			// gmp_printf("RSA Key Generation\n");
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("p\n------------------------------------------------\n%Zd\n", K.p);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("q\n------------------------------------------------\n%Zd\n", K.q);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("n\n------------------------------------------------\n%Zd\n", K.n);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("e\n------------------------------------------------\n%Zd\n", K.e);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("d\n------------------------------------------------\n%Zd\n", K.d);
			// gmp_printf("---------------------------------------------------\n");

			kem_decrypt(fnOut, fnIn, &K);

			break;

		// Generate a nBit key, and save to tmp/testkey{,.pub}:
		case GEN:
			// printf("Generating Key\n");
			// public and private file name
			strcpy(f_pub, fnOut);
			strcat(f_pub, ".pub");
			strcpy(f_prvt, fnOut);
			strcat(f_prvt, ".prvt");

			// printf("public filepath - %s\n", f_pub);
			// printf("private filepath - %s\n", f_prvt);
			rsa_keyGen(nBits, &K);
			
			// mpz_abs(K.d, K.d);

			// printf("WRINTING THIS KEY BELOW TO THE FILE\n");
			// gmp_printf("---------------------------------------------------\n");
			// gmp_printf("RSA Key Generation\n");
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("p\n------------------------------------------------\n%Zd\n", K.p);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("q\n------------------------------------------------\n%Zd\n", K.q);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("n\n------------------------------------------------\n%Zd\n", K.n);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("e\n------------------------------------------------\n%Zd\n", K.e);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("d\n------------------------------------------------\n%Zd\n", K.d);
			// gmp_printf("---------------------------------------------------\n");
			
			// needed to mul by -1, because d was negative sometimes.
			// mpz_t x; 
			// mpz_init(x);
			// mpz_set_si(x, -1);
			// mpz_mul(K.d, K.d, x);

			// if (K.d < 0)
			// {
			// 	printf("negative\n");
			// 	mpz_t x;
			// 	mpz_init(x);
			// 	mpz_set_si(x, -1);
			// 	mpz_mul(K.d, K.d, x);
			// }
			// else
			// 	printf("posicute\n");
			/* only write n, e */
			f_Public = fopen(f_pub, "w+b");
			rsa_writePublic(f_Public, &K);
			fclose (f_Public);

			// /* write p, q, d */
			f_Private = fopen(f_prvt, "w+b");
			rsa_writePrivate(f_Private, &K);
			fclose (f_Private);

			// // printf("THIS IS WHAT I READ FROM THE public FILE \n");

			// RSA_KEY _K1;
			// FILE* f_Public_11;
			// f_Public_11 = fopen(f_pub, "r+b");
			// rsa_readPublic(f_Public_11, &_K1);		/* set n, e */

			// gmp_printf("---------------------------------------------------\n");
			// gmp_printf("RSA Key Generation\n");
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("n\n------------------------------------------------\n%Zd\n", _K1.n);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("e\n------------------------------------------------\n%Zd\n", _K1.e);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("p\n------------------------------------------------\n%Zd\n", _K1.p);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("q\n------------------------------------------------\n%Zd\n", _K1.q);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("d\n------------------------------------------------\n%Zd\n", _K1.d);
			// gmp_printf("---------------------------------------------------\n");
			
			// fclose (f_Public_11);

			// rsa_shredKey(&_K1);

			// // printf("THIS IS WHAT I READ FROM THE private FILE\n");
			
			// RSA_KEY _K;
			// FILE* f_Prvt_1;
			// f_Prvt_1 = fopen(f_prvt, "r");
			// rsa_readPrivate(f_Prvt_1, &_K);		/* set n, e */

			// gmp_printf("---------------------------------------------------\n");
			// gmp_printf("RSA Key Generation\n");
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("n\n------------------------------------------------\n%Zd\n", _K.n);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("e\n------------------------------------------------\n%Zd\n", _K.e);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("p\n------------------------------------------------\n%Zd\n", _K.p);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("q\n------------------------------------------------\n%Zd\n", _K.q);
			// gmp_printf("---------------------------------------------------\n");

			// gmp_printf("d\n------------------------------------------------\n%Zd\n", _K.d);
			// gmp_printf("---------------------------------------------------\n");
			
			// fclose (f_Prvt_1);

			// rsa_shredKey(&_K);

			// printf("finshed generating key...\n");

			break;
		default:
			return 1;
	}

	rsa_shredKey(&K);

	return 0;
}
