/*
Titel: openssl
Beschreibung: openssl.c ueberprueft zunaechst die Aussage, ob der Text "Schoene Crypto Welt" mit dem
Key und IV="BBBBBBBBBBBBBBBB" unter aes128_cbc den Ciphertext
"AAE365272C81078AB6116B361831D0F6A5D3C8587E946B530B7957543107F15E" ergibt. Anschließend kann der User
von ihm eingegebene Texte mit von ihm gewählten Schlüsseln und Init-Vektoren entweder ver- oder 
entschluesseln lassen.
Quelle: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
Autor: Patrick Wintner
GitHub: https://github.com/EternalNothingness/FSST-5BHEL-Excercises-10_openssl.git
Datum der letzten Bearbeitung: 15.03.2021
*/

#include <stdlib.h>
#include <stdio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define ENCTXT 1
#define DECTXT 2

// -- Initialisierung der Funktionen --
void handleErrors(void);
int menu(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);
char *str2hex(char* str);
char *getdata(char* info, int len, char *cond, int whitespaceena);

int main (void)
{
	printf("\nTest Run\n");
	printf("========\n\n");

	/* Message to be encrypted */
	unsigned char *plaintext = malloc(sizeof(char));
	plaintext = (unsigned char *)"Schoene Crypto Welt";
	printf("Plaintext is: %s\n", plaintext);

	/* A 128 bit key */
	unsigned char *key = malloc(sizeof(char)); 
	key = (unsigned char *)"BBBBBBBBBBBBBBBB";
	printf("Key is: %s\n", key);

	/* A 128 bit IV */
	unsigned char *iv = malloc(sizeof(char));
	iv = (unsigned char *)"BBBBBBBBBBBBBBBB";
	printf("IV is: %s\n\n", iv);

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

	/* create verification ciphertext*/
	char *ciphertext_should_str;
	ciphertext_should_str = "AAE365272C81078AB6116B361831D0F6A5D3C8587E946B530B7957543107F15E";
	unsigned char *ciphertext_should_hex = malloc(sizeof(char));
	ciphertext_should_hex=str2hex(ciphertext_should_str); // Turns text (e.g. 'a') into hexadecimal values (0xa=15)
	printf("Ciphertext should:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext_should_hex, strlen(ciphertext_should_hex));

	/* verify ciphertext*/
	int cnt_err = 0;
	for(int i = 0; i<ciphertext_len; i++){
		if(ciphertext[i] != *(ciphertext_should_hex+i)) cnt_err++;
		if(i+1==ciphertext_len) printf("\nComparison finished with %i errors\n", cnt_err);
	}

	// -- main loop --
	for(;;){
		int choice = menu();
		if((choice<ENCTXT)||(choice>DECTXT)) return 0;

		key=getdata("\nEnter key:", 16, "eq", 0); // defines a 16byte key
		iv=getdata("Enter init vector:", 16, "eq", 0); // defines a 16byte init vector

		if(choice==ENCTXT){
			plaintext=getdata("Enter plaintext:", 1, "min", 1); // defines plaintext with a minimum length of 1byte
			ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv, ciphertext);
			printf("Encrypted text is:\n");
			BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
		}
		else if(choice==DECTXT){
			ciphertext_should_hex=str2hex(getdata("Enter ciphertext:", 1, "min", 1)); // defines ciphertext with a minimum length of 1byte
			for(int i = 0; i<strlen(ciphertext_should_hex); i++){
				ciphertext[i] = *(ciphertext_should_hex+i);
				if(i+1==ciphertext_len) ciphertext[i+1] = *(ciphertext_should_hex+i+1); // adds '\0'
			}
			decryptedtext_len = decrypt(ciphertext, strlen(ciphertext), key, iv, decryptedtext);
			decryptedtext[decryptedtext_len] = '\0'; // adds zero-terminator
			printf("Decrypted text is:\n");
			printf("%s\n\n", decryptedtext);
		}
	}
	return 0;
}

// -- Funktion void handleErrors(void) --
// Parameter: -
// Beschreibung: gibt bei Auftreten von Fehlern im Zusammenhang mit Kryptologie Fehlermeldungen aus 
// und beendet das Programm
// Rueckgabewert: -
void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

// -- Funktion int menu(void) --
// Parameter: -
// Beschreibung: Menu, welches durch Benutzer-Eingabe bestimmt, ob ein Text verschluesselt oder
// entschluesselt werden soll
// Rueckgabewert: Auswahl des Benutzers
int menu(void){
	int i;
	printf("\nWhat do you want to do?\n");
	printf("    (1) Encrypt a text\n");
	printf("    (2) Decrypt a text\n");
	printf("    (other) Exit program\n");
	printf("Please choose an option: ");
	scanf(" %c", &i);
	getchar(); // intercepts additional entered letters
	return i-'0';
}

// -- Funktion int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) --
// Parameter:
//	* char *plaintext ... zu verschluesselnder Text
//	* int plaintext_len ... Laenge des Plaintexts
//	* unsigned char *key ... Schluessel
//	* unsigned char *iv ... Init-Vektor
//	* unsigned char *ciphertext ... Pointer, in welchem der verschluesselte Text geschrieben wird
// Beschreibung: encrypt() verschluesselt den Plaintext mit dem angegebenen Key und Init-Vektor und
// schreibt das Ergebnis in den Pointer ciphertext.
// Rueckgabewert: Laenge des Ciphertexts
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

// -- Funktion int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) --
// Parameter:
//	* char *ciphertext ... zu entschluesselnder Text
//	* int ciphertext_len ... Laenge des Ciphertexts
//	* unsigned char *key ... Schluessel
//	* unsigned char *iv ... Init-Vektor
//	* unsigned char *plaintext ... Pointer, in welchem der entschluesselte Text geschrieben wird
// Beschreibung: decrypt() entschluesselt den Ciphertext mit dem angegebenen Key und Init-Vektor und
// schreibt das Ergebnis in den Pointer plaintext.
// Rueckgabewert: Laenge des Plaintexts
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

// -- Funktion char *str2hex(char *str) --
// Parameter: char *str ... umzuwandelnder String
// Beschreibung: str2hex() wandelt den Inhalt des Strings (unter der Annahme, dass dieser nur die 
// Buchstaben a-f - egal ob Gross- oder Kleinschreibung - und die Ziffern 0-9 enthaelt) diesen 
// paarweise in die entsprechenden hexadizimalen Werte um (z. B. str = "aab1c4" => aa b1 c4 =>
// 10*16+10 11*16+1 12*16+4).
// Rueckgabewert: umgewandelter String
char *str2hex(char *str){
	int hex1; // 16er-Stelle
	int hex0; // 1er-Stelle
	unsigned char *result = malloc(sizeof(char*));
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
	return result;
}

// -- Funktion char *getdata(char *info, int len, char *cond, int whitespaceena) --
// Parameter:
//	* char *info ... wird dem Benutzer als Information, was er einzugeben habe, auf der Konsole
//	ausgegeben
//	* int len, char *cond ... legen zusammen fest, wie lang die Eingabe des Benutzers sein darf
//	* int whitespaceena ... legt fest, ob whitespaces bei der Eingabe beruecksichtigt werden (0 ->
//	Whitespaces werden als Eingabeende interpretiert, -> Whitespaces werden beruecksichtigt)
// Beschreibung: getdata() ermoeglicht es dem Benutzer, geforderte Daten einzugeben. Der String info
// wird auf der Konsole augegeben und soll den Benutzer darueber informieren, was er einzugeben habe.
// Die Laenge bestimmt im Zusammenhang mit cond, lang die Eingabe des Users sein darf. Wenn cond="min"
// ist, so muss der eingegebene String die entsprechende Mindestlaenge haben. Bei cond="max" darf
// dieser die vorgegebene Laenge nicht ueberschreiten. Sollte cond="eq" sein, so muss die Laenge des
// eingegebenen Strings genau dem Wert von len in Bytes entsprechen. Bei falschen Eingaben wird der
// Benutzer zur erneuten Eingabe aufgefordert.
// Rueckgabewert: User-Eingabe
char *getdata(char *info, int len, char *cond, int whitespaceena){
	char *buffer = malloc(sizeof(char*));
	for(;;){
		memset(buffer,0,sizeof(char*));
		printf("%s (%s %i Byte) ", info, cond, len);
		if(whitespaceena==1) scanf(" %[^\n]254s", buffer);
		else scanf(" %s", buffer);
		if(cond=="eq"){
			if(strlen(buffer)==len) break;
			printf("invalid input\n");
			printf("length was %i Byte long, but should be equal to %i Byte\n", strlen(buffer), len);
		}
		else if(cond=="min"){
			if(strlen(buffer)>=len) break;
			printf("invalid input\n");
			printf("length was %i Byte long, but should be minimal %i Byte\n", strlen(buffer), len);
		}
		else if(cond=="max"){
			if(strlen(buffer)<=len) break;
			printf("invalid input\n");
			printf("length was %i Byte long, but should be maximal %i Byte\n", strlen(buffer), len);
		}
	}
	return buffer;
}
