#include <stdio.h>
#include <string.h>
#include "rectangle.h"
#define HEX(x) (x > 9 ?('A' + (x - 10)) :('0' + x))

void main()
{
	int i, j;

	// Testing key generation...
	uint32_t main_key[] = {	0xFFFFFFFF,
							0xFFFFFFFF,
							0xFFFFFFFF,
							0xFFFFFFFF
						};

	rcipher_params_t cipher_params = rectangle_init_key(main_key);

	for(i = 0; i < 25; ++i)
	{
		if(i != 24)
			get_round_key(cipher_params);
		else
			get_key25(cipher_params);
					
		printf("Sub-key of round %d:\n", i + 1);

		for(j = 0; j < 4; ++j)
			printf("%04x\n", cipher_params->sub_key[j]);
		printf("\n");
	}

	rectangle_destroy(cipher_params);
	

	// Testing encryption...
	printf("\n\nTesting encryption...\n");
	cipher_params = rectangle_init_key(main_key);
	char ptext[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	ciphertext_t ctext_struct;
	printf("PText in string:\t%s\n", ptext);
	printf("Plaintext in hex:\t");
	int len = strlen(ptext) + 1;

	for(i = 0; i < len; ++i)
	{
		char low = ptext[i] & 0x0f;
		char high = ((unsigned char)ptext[i]) >> 4;
		printf("%c%c", HEX(high), HEX(low));

		if(i & 1)
			printf(" ");
	}
	printf("\n\n");

	ctext_struct = encrypt(cipher_params, ptext);

	printf("Ciphertext in hex:\t");
	for(i = 0; i < ctext_struct->length; ++i)
	{
		char low = ctext_struct->ctext[i] & 0x0f;
		char high = ((unsigned char)ctext_struct->ctext[i]) >> 4;
		printf("%c%c", HEX(high), HEX(low));

		if(i & 1)
			printf(" ");
	}
	printf("\nCText as string: \t");
	for(i = 0; i < ctext_struct->length; ++i)
		printf("%c", ctext_struct->ctext[i]);
		
	destroy_ctext(ctext_struct);

	rectangle_destroy(cipher_params);
	printf("\n");
}


/*
	Correct output:
	1110 1000 0011 1110		e83e
	1110 1111 1110 1110		efee
	0100 1010 0001 0101		4a15
	0111 1010 0100 0110		7a46
*/