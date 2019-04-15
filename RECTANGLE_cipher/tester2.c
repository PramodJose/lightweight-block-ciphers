#include <stdio.h>
#include <stdint.h>
#include "rectangle.h"

void main()
{
	int i, j;
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


	printf("\n\nTesting encryption...\n");
	cipher_params = rectangle_init_key(main_key);

	union state ctext_struct;
	
	for(i = 0; i < 4; ++i)
	{
		ctext_struct.byte_array[i] = 0xffff;
		printf("%04x\n", ctext_struct.byte_array[i]);
	}

	encrypt_64bit_block(cipher_params, &ctext_struct);

	printf("\nCiphertext:\n");
	for(i = 0; i < 4; ++i)
		printf("%04x\n", ctext_struct.byte_array[i]);

	rectangle_destroy(cipher_params);
}
