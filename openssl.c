/*
Titel: openssl
Beschreibung:
Quelle: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
Autor: Patrick Wintner
GitHub: https://github.com/EternalNothingness/FSST-5BHEL-Excercises-10_openssl.git
Datum der letzten Bearbeitung: 10.03.2021
*/

#include <stdlib.h>
#include <stdio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

// -- Initialisierung der Funktionen --
void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);
void str2hex(char* str, unsigned char* result);

int main (void)
{
	for(;;){
		/* A 128 bit key */
		unsigned char *key = malloc(sizeof(char*));
		for(;;){
			memset(key,0,sizeof(key));
			printf("Key: ");
			scanf(" %s", key);
			if(strlen(key)==16) break;
			printf("Ungueltige Eingabe\n");
			printf("Key length: %i\n", strlen(key));
		}
		//key = (unsigned char *)"BBBBBBBBBBBBBBBB";

		/* A 128 bit IV */
		unsigned char *iv = malloc(sizeof(char*));
		for(;;){
			memset(iv,0,sizeof(iv));
			printf("iv: ");
			scanf(" %s", iv);
			if(strlen(iv)==16) break;
			printf("Ungueltige Eingabe\n");
			printf("iv length: %i\n", strlen(iv));
		}
		//iv = (unsigned char *)"BBBBBBBBBBBBBBBB";

		/* Message to be encrypted */
		unsigned char *plaintext = malloc(sizeof(char**));
		for(int i=0;i<10;i++){
			memset(plaintext,0,sizeof(plaintext));
			printf("plaintext: ");
			scanf(" %[^\n]254s", plaintext);
			if(plaintext!=0) break;
		}
		//plaintext = (unsigned char *)"Schoene Crypto Welt";

		/*
		* Buffer for ciphertext. Ensure the buffer is long enough for the
		* ciphertext which may be longer than the plaintext, depending on the
		* algorithm and mode.
		*/
		unsigned char ciphertext[128];
		/* Buffer for the decrypted text */
		unsigned char decryptedtext[128];
	
		int decryptedtext_len, ciphertext_len;

		/* Encrypt the plaintext */
		ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv, ciphertext);

		/* Do something useful with the ciphertext here */
		/*
		printf("Ciphertext is:\n");
		BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
		*/
		// --------------------------------------------------------------------------------------------------------------------------
		printf("Ciphertext is:\n");
		for(int i=0;i<ciphertext_len;i++){
			printf("%x ", *(ciphertext+i));
			if(i+1==ciphertext_len) printf("\n");
		}

		char* ciphertext_should_str;
		ciphertext_should_str = "AAE365272C81078AB6116B361831D0F6A5D3C8587E946B530B7957543107F15E";
		unsigned char* ciphertext_should_hex = malloc(sizeof(char*));
		str2hex(ciphertext_should_str, ciphertext_should_hex);
		printf("Ciphertext should:\n");
		for(int i=0;*(ciphertext_should_hex+i)!=0;i++){
			printf("%x ", *(ciphertext_should_hex+i));
			if(*(ciphertext_should_hex+i+1)==0)printf("\n");
		}

		int cnt_err = 0;
		for(int i = 0; i<ciphertext_len; i++){
			if(ciphertext[i] != *(ciphertext_should_hex+i)) cnt_err++;
			if(i+1==ciphertext_len) printf("Test finished with %i errors\n", cnt_err);
		}

		// -------------------------------------------------------------------------------------------------------------
		/* Decrypt the ciphertext */
		decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
		decryptedtext);

		/* Add a NULL terminator. We are expecting printable text */
		decryptedtext[decryptedtext_len] = '\0';

		/* Show the decrypted text */
		printf("Decrypted text is:\n");
		printf("%s\n", decryptedtext);
	}
	return 0;
}


void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
	handleErrors();

	/*
	* Initialise the encryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 128 bit AES (i.e. a 128 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits
	*/
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
	handleErrors();

	/*
	* Provide the message to be encrypted, and obtain the encrypted output.
	* EVP_EncryptUpdate can be called multiple times if necessary
	*/
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/*
	* Finalise the encryption. Further ciphertext bytes may be written at
	* this stage.
	*/
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/*
	* Initialise the decryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 128 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits
	*/
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		handleErrors();

	/*
	* Provide the message to be decrypted, and obtain the plaintext output.
	* EVP_DecryptUpdate can be called multiple times if necessary.
	*/
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/*
	* Finalise the decryption. Further plaintext bytes may be written at
	* this stage.
	*/
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

void str2hex(char *str, unsigned char *result){
	int hex1;
	int hex0;
	for(int i=0;;i++){
		if(*(str+i)==0) break;
		else if(*(str+i)=='a'||*(str+i)=='A') hex1=10;
		else if(*(str+i)=='b'||*(str+i)=='B') hex1=11;
		else if(*(str+i)=='c'||*(str+i)=='C') hex1=12;
		else if(*(str+i)=='d'||*(str+i)=='D') hex1=13;
		else if(*(str+i)=='e'||*(str+i)=='E') hex1=14;
		else if(*(str+i)=='f'||*(str+i)=='F') hex1=15;
		else hex1=*(str+i)-'0';
		i++;

		if(*(str+i)==0) break;
		else if(*(str+i)=='a'||*(str+i)=='A') hex0=10;
		else if(*(str+i)=='b'||*(str+i)=='B') hex0=11;
		else if(*(str+i)=='c'||*(str+i)=='C') hex0=12;
		else if(*(str+i)=='d'||*(str+i)=='D') hex0=13;
		else if(*(str+i)=='e'||*(str+i)=='E') hex0=14;
		else if(*(str+i)=='f'||*(str+i)=='F') hex0=15;
		else hex0=*(str+i)-'0';
		*(result+(i/2))=16*hex1+hex0;
		if(*(str+i+1)==0) *(result+(i/2)+1)=0;
	}
}
