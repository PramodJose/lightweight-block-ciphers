#include <stdio.h>
#include <string.h>
#include "rectangle.h"
#define HEX(x) (x > 9 ?('A' + (x - 10)) :('0' + x))


void print_info()
{
	printf("Note:\tWhile analyzing this output, please keep in mind that every pair of bytes is\n");
	printf("\tflipped because of the little-endian architecture of Intel CPUs.\n");
	printf("\tFor example, if the string in hexadecimal is displayed as: \"1186 F53E B458 5F8B\",\n\tthen, internally it is represented as:\n");
	printf("\t\t8611\n\t\t3EF5\n\t\t58B4\n\t\t8B5F\n\t[The 64-bit cipher state is represented as a matrix such as this one.\n\tRefer to Figure 1 in the paper for more information on this.]\n");
	printf("\tIn other words, the LSB is displayed first (little-endianess) in a pair of bytes\n\tdisplayed below. Each pair of bytes is separated by a space for ease of readability.\n\n");
	printf("==================================================================================================\n\n");
}

void print_in_hex(string_t string)
{
	for(size_t i = 0; i < string->length; ++i)
	{
		char low = string->str[i] & 0x0f;
		char high = ((unsigned char)string->str[i]) >> 4;
		printf("%c%c", HEX(high), HEX(low));

		if(i & 1)
			printf(" ");
	}

	printf("\nAnd as a string:\t");
	for(size_t i = 0; i < string->length && string->str[i] != 0; ++i)
		printf("%c", string->str[i]);
	
	printf("\nString length:\t\t%ld\n\n", string->length);
}

void main()
{
	int i, j;

	// Input your 128 bit key here (as hex)...
	uint32_t main_key[] = {	0x00000000,
							0x00000000,
							0x00000000,
							0x00000000
						};

	rcipher_params_t cipher_params = rectangle_init_key(main_key);

	// Input your plaintext here..
	// ..either as a byte array..
	char ptext[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	string_t plaintext = init_string_bytes(ptext, sizeof(ptext));

	// ..or as a string.
	/*char *ptext = "The author of this piece of code is Pramod.";
	string_t plaintext = init_string(ptext);*/
	
	print_info();
	printf("Plaintext in hex:\t");
	print_in_hex(plaintext);

	string_t ciphertext, decrypted_ptext;
	ciphertext = encrypt(cipher_params, plaintext);

	printf("Ciphertext in hex:\t");
	print_in_hex(ciphertext);

	decrypted_ptext = decrypt(cipher_params, ciphertext);
	printf("Decrypted ptext in hex:\t");
	print_in_hex(decrypted_ptext);

	destroy_string(decrypted_ptext);
	destroy_string(plaintext);
	destroy_string(ciphertext);
	rectangle_destroy(cipher_params);
}
