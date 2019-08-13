/*
**	AUTHOR:	Pramod Jose
**	GITHUB:	github.com/PramodJose
**	DATE:	08 August 2019
*/

#ifndef _TREK_CIPHER_H
#define _TREK_CIPHER_H 1
#define HEX(x) (x > 9 ?('A' + (x - 10)) :('0' + x))

#define MAIN_KEY_SIZE 10
#define ROUND_KEY_SIZE 8
#define BLOCK_SIZE 8
#define ROUNDS 20


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct tcipher_params
{
	uint8_t main_key[MAIN_KEY_SIZE];
	uint8_t round_key[ROUND_KEY_SIZE];
	uint8_t round_constant;
};

typedef struct tcipher_params* tcipher_params_t;

tcipher_params_t trek_init()
{
	tcipher_params_t parameters = malloc(sizeof(struct tcipher_params));

	if(parameters == NULL)
	{
		perror("Could not allocate memory in trek_init(). File: trek_cbc.h\nError");
		exit(EXIT_FAILURE);
	}

	// Row constant has to be initialised to 0x1.
	parameters->round_constant = 0x01;
	return parameters;
}

tcipher_params_t trek_init_key(uint8_t main_key[])
{
	tcipher_params_t parameters = trek_init();
	int8_t i;

	for(i = 0; i < MAIN_KEY_SIZE; ++i)
		parameters->main_key[i] = main_key[i];

	return parameters;
}

tcipher_params_t trek_init_copy(tcipher_params_t params)
{
	tcipher_params_t parameters = trek_init();
	int8_t i;

	for(i = 0; i < MAIN_KEY_SIZE; ++i)
		parameters->main_key[i] = params->main_key[i];

	return parameters;
}

tcipher_params_t trek_params_copy(tcipher_params_t dest, tcipher_params_t src)
{
	int8_t i;
	dest->round_constant = src->round_constant;

	for(i = 0; i < ROUND_KEY_SIZE; ++i)
	{
		dest->main_key[i] = src->main_key[i];
		dest->round_key[i] = src->round_key[i];
	}

	for(i = ROUND_KEY_SIZE; i < MAIN_KEY_SIZE; ++i)
		dest->main_key[i] = src->main_key[i];

	return dest;
}

void trek_destroy(tcipher_params_t parameters)
{
	if(parameters != NULL)
	{
		free(parameters);
		parameters = NULL;
	}
}

void trek_LFSR(uint8_t *round_constant)
{
	if(*round_constant == 0)
		*round_constant = 1;
	else
	{
		uint8_t new_rc0 = ((*round_constant & 0x10) > 0) ^ ((*round_constant & 0x08) > 0); 

		*round_constant <<= 1;

		*round_constant &= 0x1F;

		*round_constant |= new_rc0;
	}
}

void s_box(uint8_t *x)
{
	const uint8_t table[] = { 	0x07,
							  	0x04,
								0x0A,
								0x09,
								0x01,
								0x0F,
								0x0B,
								0x00,
								0x0C,
								0x03,
								0x02,
								0x06,
								0x08,
								0x0E,
								0x0D,
								0x05
							};
	if(*x >= 0x00 && *x <= 0x0F)	// Basic error checking.
		*x = table[*x];
}

// Involutive S-Box, hence we can simply call the main S-Box function.
void inverse_s_box(uint8_t *x)
{
	return s_box(x);
}

// debug code
void print_main_key(tcipher_params_t parameters)
{
	int8_t i;
	for(i = 0; i < MAIN_KEY_SIZE; ++i)
		printf("%02x ", parameters->main_key[i]);
	printf("\n");
}

// ------------------------ KEY SCHEDULE (80 BIT KEY) ------------------------

uint8_t* get_round_key(tcipher_params_t parameters)
{
	int8_t i;

	/*	S-box is first applied to the first 4 nibbles (least significant) of the key.
	**	That's why we are using main_key[9] and main_key[8].
	*/
	uint8_t nib0 = parameters->main_key[MAIN_KEY_SIZE - 1] & 0x0F, nib1 = (parameters->main_key[MAIN_KEY_SIZE - 1] >> 4);
	s_box(&nib0);
	s_box(&nib1);
	parameters->main_key[MAIN_KEY_SIZE - 1] = (nib1 << 4) | nib0;

	nib0 = parameters->main_key[MAIN_KEY_SIZE - 2] & 0x0F;
	nib1 = (parameters->main_key[MAIN_KEY_SIZE - 2] >> 4);
	s_box(&nib0);
	s_box(&nib1);
	parameters->main_key[MAIN_KEY_SIZE - 2] = (nib1 << 4) | nib0;

	// Block Shuffling Table.
	const uint8_t block_shuffle[] = {5, 0, 1, 4, 7, 12, 3, 8, 13, 6, 9, 2, 15, 10, 11, 14, 19, 18, 16, 17};
	uint8_t updated_key[MAIN_KEY_SIZE] = {0};


	// Going over each nibble for the block shuffle.
	for(i = 0; i < MAIN_KEY_SIZE * 2; ++i)
	{
		uint8_t src_index = MAIN_KEY_SIZE - 1 - (i >> 1), result = block_shuffle[i], \
				dest_index = MAIN_KEY_SIZE - 1 - (result >> 1), src_nibble;

		// If we are looking at the upper nibble (i), then save it.
		if(i & 1)
			src_nibble = parameters->main_key[src_index] >> 4;
		else	// Else, save the lower nibble.
			src_nibble = parameters->main_key[src_index] & 0x0F;

		// If we want to modify the upper nibble, then retain the lower nibble of updated_key
		// and bitwise OR the upper nibble.
		if(result & 1)
			updated_key[dest_index] = (updated_key[dest_index] & 0x0F) | (src_nibble << 4);
		else 	// else, do the opposite of that.
			updated_key[dest_index] = (updated_key[dest_index] & 0xF0) | src_nibble;
	}

	// Copy the updated key back to the main key.
	for(i = 0; i < MAIN_KEY_SIZE; ++i)
		parameters->main_key[i] = updated_key[i];

	// Add Round constant.
	parameters->main_key[MAIN_KEY_SIZE - 1] ^= parameters->round_constant;

	// Get the next round constant.
	trek_LFSR(&parameters->round_constant);

	// Extracting the round key.
	for(i = 0; i < ROUND_KEY_SIZE; ++i)
		parameters->round_key[ROUND_KEY_SIZE - 1 - i] = parameters->main_key[MAIN_KEY_SIZE - 1 - i];

	return parameters->round_key;
}


// ------------------------ ENCRYPTION ------------------------


uint8_t* encrypt_64bit_block(tcipher_params_t parameters, uint8_t* cipher_state)
{
	int8_t round_no, i;

	// Key whitening. XORing the 64 bit cipher state with the least significant 64 bits of the main key.
	for(i = 0; i < BLOCK_SIZE; ++i)
		cipher_state[BLOCK_SIZE - 1 - i] ^= parameters->main_key[BLOCK_SIZE - 1 - i];


	for(round_no = 0; round_no < ROUNDS; ++round_no)
	{
		// Substitute nibbles.
		for(i = 0; i < BLOCK_SIZE; ++i)
		{
			uint8_t nib0 = cipher_state[i] & 0x0F, nib1 = cipher_state[i] >> 4;
			s_box(&nib0);
			s_box(&nib1);

			cipher_state[i] = (nib1 << 4) | nib0;
		}

		// Block Shuffling Table.
		const uint8_t block_shuffle[] = {5, 0, 1, 4, 7, 12, 3, 8, 13, 6, 9, 2, 15, 10, 11, 14};
		uint8_t updated_cipher_state[BLOCK_SIZE] = {0};
		
		// Going over each nibble for the block shuffle.
		for(i = 0; i < BLOCK_SIZE * 2; ++i)
		{
			uint8_t src_index = BLOCK_SIZE - 1 - (i >> 1), result = block_shuffle[i], \
					dest_index = BLOCK_SIZE - 1 - (result >> 1), src_nibble;

			// If we are looking at the upper nibble (i), then save it.
			if(i & 1)
				src_nibble = cipher_state[src_index] >> 4;
			else	// Else, save the lower nibble.
				src_nibble = cipher_state[src_index] & 0x0F;

			// If we want to modify the upper nibble, then retain the lower nibble of updated_cipher_state
			// and bitwise OR the upper nibble.
			if(result & 1)
				updated_cipher_state[dest_index] = (updated_cipher_state[dest_index] & 0x0F) | (src_nibble << 4);
			else 	// else, do the opposite of that.
				updated_cipher_state[dest_index] = (updated_cipher_state[dest_index] & 0xF0) | src_nibble;
		}

		get_round_key(parameters);

		// Copy the result of (updated_cipher_state ^ round_key) to cipher_state.
		for(i = 0; i < BLOCK_SIZE; ++i)
			cipher_state[i] = updated_cipher_state[i] ^ parameters->round_key[i];
	}

	return cipher_state;
}

void encrypt(uint8_t* IV, uint8_t* key, FILE* ptext_stream, FILE* ctext_stream)
{
	uint8_t buffer[BLOCK_SIZE + 1], pad_byte;
	int8_t n, i;
	tcipher_params_t parameters = trek_init_key(key), cipher_params = trek_init_copy(parameters);

	while(1)
	{
		n = fread(buffer, sizeof(char), BLOCK_SIZE, ptext_stream);

		// PKCS #5 - padding.
		for(pad_byte = BLOCK_SIZE - n, i = n; i < BLOCK_SIZE; ++i)
			buffer[i] = pad_byte;

		// XORing plaintext with the IV.
		for(i = 0; i < BLOCK_SIZE; ++i)
			buffer[i] ^= IV[i];

		encrypt_64bit_block(cipher_params, buffer);

		// Writing encrypted block to output stream.
		fwrite(buffer, sizeof(char), BLOCK_SIZE, ctext_stream);

		// If it is the end of the ptext_stream, then end the loop.
		if(n < BLOCK_SIZE)
			break;

		// Updating IV for the next block.
		for(i = 0; i < BLOCK_SIZE; ++i)
			IV[i] = buffer[i];

		trek_params_copy(cipher_params, parameters);
	}

	trek_destroy(parameters);
	trek_destroy(cipher_params);
}


// ------------------------ DECRYPTION ------------------------


struct round_key
{
	uint8_t key[ROUND_KEY_SIZE];
} round_keys[ROUNDS];

typedef struct round_key* round_key_t;


round_key_t store_round_keys(tcipher_params_t parameters, round_key_t keys)
{
	int8_t i, j;
	tcipher_params_t params = trek_init_copy(parameters);

	for(i = 0; i < ROUNDS; ++i)
	{
		get_round_key(params);

		for(j = 0; j < ROUND_KEY_SIZE; ++j)
			keys[i].key[j] = params->round_key[j];
	}

	trek_destroy(params);
	return keys;
}


uint8_t* decrypt_64bit_block(tcipher_params_t parameters, uint8_t* cipher_state)
{
	int8_t round_no, i;

	store_round_keys(parameters, round_keys);

	for(round_no = ROUNDS - 1; round_no >= 0; --round_no)
	{
		// Add Round Key.
		for(i = 0; i < BLOCK_SIZE; ++i)
			cipher_state[i] ^= round_keys[round_no].key[i];

		// Inverse Block Shuffling Table.
		const uint8_t inverse_block_shuffle[] = {1, 2, 11, 6, 3, 0, 9, 4, 7, 10, 13, 14, 5, 8, 15, 12};
		uint8_t updated_cipher_state[BLOCK_SIZE] = {0};

		// Going over each nibble for the inverse block shuffle.
		for(i = 0; i < BLOCK_SIZE * 2; ++i)
		{
			uint8_t src_index = BLOCK_SIZE - 1 - (i >> 1), result = inverse_block_shuffle[i], \
					dest_index = BLOCK_SIZE - 1 - (result >> 1), src_nibble;

			// If we are looking at the upper nibble (i), then save it.
			if(i & 1)
				src_nibble = cipher_state[src_index] >> 4;
			else	// Else, save the lower nibble.
				src_nibble = cipher_state[src_index] & 0x0F;

			// If we want to modify the upper nibble, then retain the lower nibble of updated_cipher_state
			// and bitwise OR the upper nibble.
			if(result & 1)
				updated_cipher_state[dest_index] = (updated_cipher_state[dest_index] & 0x0F) | (src_nibble << 4);
			else 	// else, do the opposite of that.
				updated_cipher_state[dest_index] = (updated_cipher_state[dest_index] & 0xF0) | src_nibble;
		}

		// Substitute nibbles.
		for(i = 0; i < BLOCK_SIZE; ++i)
		{
			uint8_t nib0 = updated_cipher_state[i] & 0x0F, nib1 = updated_cipher_state[i] >> 4;
			inverse_s_box(&nib0);
			inverse_s_box(&nib1);

			cipher_state[i] = (nib1 << 4) | nib0;
		}
	}

	for(i = 0; i < BLOCK_SIZE; ++i)
		cipher_state[BLOCK_SIZE - 1 - i] ^= parameters->main_key[BLOCK_SIZE - 1 - i];
}


void decrypt(uint8_t* IV, uint8_t* key, FILE* ptext_stream, FILE* ctext_stream)
{
	uint8_t buffer[BLOCK_SIZE + 1], pad_byte, IV_copy[BLOCK_SIZE];
	int8_t n, i, j;
	tcipher_params_t cipher_params = trek_init_key(key);

	for(j = 0; ; j = 1)
	{
		// read from ctext stream into IV_copy..
		n = fread(IV_copy, sizeof(char), BLOCK_SIZE, ctext_stream);

		// if it is the last block, then we need to remove/check padding from the previous block.
		if(n < BLOCK_SIZE)
		{
			pad_byte = buffer[BLOCK_SIZE - 1];

			for(i = BLOCK_SIZE - pad_byte; i < BLOCK_SIZE; ++i)
				if(buffer[i] != pad_byte)
				{
					errno = EBADMSG;
					perror("Error while decrypting! Possibly invalid key.\nError");
					exit(EXIT_FAILURE);
				}

			fwrite(buffer, BLOCK_SIZE - pad_byte, sizeof(char), ptext_stream);
			break;
		}
		// else if it is not the last block and it is is not the first time we entered the main loop,
		// then write the last unencrypted block to the output stream.
		else if(j)
			fwrite(buffer, sizeof(char), BLOCK_SIZE, ptext_stream);

		// copy to buffer for decryption.
		for(i = 0; i < BLOCK_SIZE; ++i)
			buffer[i] = IV_copy[i];

		// decrypt it..
		decrypt_64bit_block(cipher_params, buffer);

		// XOR with IV; also, copy IV_copy into IV so that it can be used with the next block.
		for(i = 0; i < BLOCK_SIZE; ++i)
		{
			buffer[i] ^= IV[i];
			IV[i] = IV_copy[i];
		}
	}

	trek_destroy(cipher_params);
}

#endif
