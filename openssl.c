/*
Titel: openssl
Beschreibung:
Quelle: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
Autor: Patrick Wintner
GitHub: https://github.com/EternalNothingness/FSST-5BHEL-Excercises-10_quicksort.git
Datum der letzten Bearbeitung: 08.03.2020
*/

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
	/*
	* Set up the key and iv. Do I need to say to not hard code these in a
	* real application? :-)
	*/

	/* A 128 bit key */
	unsigned char *key = (unsigned char *)"BBBBBBBBBBBBBBBB";

	/* A 128 bit IV */
	unsigned char *iv = (unsigned char *)"BBBBBBBBBBBBBBBB";

	/* Message to be encrypted */
	unsigned char *plaintext =
	(unsigned char *)"Schoene Crypto Welt";

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
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

	// --------------------------------------------------------------------------------------------------------------------------
	printf("Ciphertext 2 is:\n");
	/*
	unsigned char* vgl_cipher = malloc(sizeof(char*));
	for(int i=0;i<ciphertext_len;i++){
		*(vgl_cipher+i) = ciphertext[i];
		if(*(ciphertext[i+1])==0) *(vgl_cipher+i+1)=0;
	}
	*/
	for(int i=0;i<ciphertext_len;i++){
		printf("%x ", *(ciphertext+i));
	}
	printf("\n");

	char* vgl;
	//vgl = "AAE365272C81078AB6116B361831D0F6A5D3C8587E946B530B7957543107F15E";
	vgl = "aae365272c81078ab6116b361831d0f6a5d3c8587e946b530b7957543107f15e";
	unsigned char* vgl_hex = malloc(sizeof(char*));
	str2hex(vgl, vgl_hex);
	printf("Ciphertext 3 is:\n");
	for(int i=0;*(vgl_hex+i)!=0;i++){
		printf("%x ", *(vgl_hex+i));
	}
	printf("\n");

	int icnterr = 0;
	for(int i = 0; i<ciphertext_len; i++){
		if(ciphertext[i] != *(vgl_hex+i)) icnterr++;
		if(i+1==ciphertext_len) printf("Test finished with %i errors\n", icnterr);
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
		else if(*(str+i)=='a') hex1=10;
		else if(*(str+i)=='b') hex1=11;
		else if(*(str+i)=='c') hex1=12;
		else if(*(str+i)=='d') hex1=13;
		else if(*(str+i)=='e') hex1=14;
		else if(*(str+i)=='f') hex1=15;
		else hex1=*(str+i)-'0';
		i++;

		if(*(str+i)==0) break;
		else if(*(str+i)=='a') hex0=10;
		else if(*(str+i)=='b') hex0=11;
		else if(*(str+i)=='c') hex0=12;
		else if(*(str+i)=='d') hex0=13;
		else if(*(str+i)=='e') hex0=14;
		else if(*(str+i)=='f') hex0=15;
		else hex0=*(str+i)-'0';
		*(result+(i/2))=16*hex1+hex0;
		if(*(str+i+1)==0) *(result+(i/2)+1)=0;
	}
}