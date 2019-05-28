/*
**	AUTHOR:	Pramod Jose
**	GITHUB:	github.com/PramodJose
**	DATE:	29 March 2019
*/

#ifndef _RECTANGLE_CIPHER_H
#define _RECTANGLE_CIPHER_H 1

/*	Definition for circular left shift.
**	Parameter 1: num is the integer variable you want to shift.
**	Parameter 2: shift is the number of places you want to shift "num" by.
**	Note: This definition has been adapted from en.wikipedia.org/wiki/Bitwise_operation#Circular_shifts.
**
**	Example:
**	uint8_t val = 0x97;
**	val	= CLSH(val, 3);
*/
#define CLSH(num, shift) ((num << shift) | (num >> (-shift & (sizeof(num) * 8 - 1))))

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>


struct rcipher_params
{
	uint32_t main_key[4];
	uint16_t sub_key[4];
	uint8_t row_constant;
};

typedef struct rcipher_params* rcipher_params_t;


/*
**	Description: Dynamically allocates memory for the cipher parameters (main_key,
**	  sub_key and row_constant). Initialises the row_constant to its default value of 0x01.
**	  Returns the address of the struct-variable which is then used by other functions.
**	Input: None.
**	Output: Returns the address of the dyamically allocated struct-variable.
**	Caveats: None
**	Thread-safe: Yes
*/
rcipher_params_t rectangle_init()
{
	rcipher_params_t parameters = malloc(sizeof(struct rcipher_params));

	if(parameters == NULL)
	{
		perror("Could not allocate memory in rectangle_init(). File: rectangle.h\nError");
		exit(EXIT_FAILURE);
	}

	// Row constant has to be initialised to 0x1.
	parameters->row_constant = 0x01;
	return parameters;
}


/*
**	Description: Behaves like a parameterised constructor. It dynamically allocates memory for
**	  the cipher parameters (main_key, sub_key and row_constant). Initialises the row_constant
**	  to its default value of 0x01. It initialises the main_key[] with the array values sent as
**	  argument. Returns the address of the struct-variable which is then used by other functions.
**	Input: An array containing 4 32 bit values (i.e. the 128-bit main key).
**	Output: Returns the address of the dyamically allocated struct-variable.
**	Caveats: None
**	Thread-safe: Yes
*/
rcipher_params_t rectangle_init_key(uint32_t main_key[])
{
	rcipher_params_t parameters = rectangle_init();
	
	parameters->main_key[0] = main_key[0];
	parameters->main_key[1] = main_key[1];
	parameters->main_key[2] = main_key[2];
	parameters->main_key[3] = main_key[3];

	return parameters;
}

rcipher_params_t rectangle_init_copy(rcipher_params_t params)
{
	rcipher_params_t parameters = rectangle_init();

	parameters->main_key[0] = params->main_key[0];
	parameters->main_key[1] = params->main_key[1];
	parameters->main_key[2] = params->main_key[2];
	parameters->main_key[3] = params->main_key[3];

	return parameters;
}

rcipher_params_t rectangle_params_copy(rcipher_params_t dest, rcipher_params_t src)
{
	char i;
	dest->row_constant = src->row_constant;

	for(i = 0; i < 4; ++i)
	{
		dest->main_key[i] = src->main_key[i];
		dest->sub_key[i] = 0;
	}

	return dest;
}

/*
**	Description: Frees the memory allocated for the struct-variable (which contains the cipher
**	  parameters).
**	Input: Address of the dynamically allocated struct-variable.
**	Output: None.
**	Caveats: None
**	Thread-safe: Yes
*/
void rectangle_destroy(rcipher_params_t parameters)
{
	if(parameters != NULL)
	{
		free(parameters);
		parameters = NULL;
	}
}


/*
**	Description: Defines/Emulates the LFSR used in the RECTANGLE cipher.
**	  Computes the next row constant given the current row constant.
**	Input: Address of the variable which contains the current row constant.
**	Output: Modifies the variable in place. After the completion of this function,
**	  the row_constant variable would contain the new row constant.
**	Caveats: row_constant should be initialised to 0x01 (the very first row
**	  constant) before this function is called.
**	Thread-safe: Yes.
*/
void rectangle_LFSR(uint8_t *row_constant)
{
	// Initialise row_constant to 1, if it is 0 (which is an invalid state).
	if(*row_constant == 0)
		*row_constant = 1;	// The very first row constant.
	else
	{
		// The new value, rc0 being computed as rc4 XOR rc2.
		uint8_t rc0 = ((*row_constant & 0x10) > 0) ^ ((*row_constant & 0x04) > 0);

		// Left shifting by 1 place.
		*row_constant <<= 1;

		// considering only the lower 5 bits.
		*row_constant &= 0x1F;

		// appending rc0...
		*row_constant |= rc0;
	}
}


/*
**	Description: Serves the purpose of the S-Box used in the RECTANGLE cipher.
**	  Given a value, x, between 0x00 and 0x0F, it finds out S(x).
**	Input: Address of the variable whose substitution value needs to be computed, i.e., x.
**	Output: Modifies the variable in place. After the completion of this function,
**	  the variable x would contain the new substitution value.
**	Caveats: None.
**	Thread-safe: Yes.
*/
void s_box(uint8_t *x)
{
	const uint8_t table[] = { 0x06,
							  0x05,
							  0x0c,
							  0x0a,
							  0x01,
							  0x0e,
							  0x07,
							  0x09,
							  0x0b,
							  0x00,
							  0x03,
							  0x0d,
							  0x08,
							  0x0f,
							  0x04,
							  0x02
							};

	if(*x >= 0x00 && *x <= 0x0F)	// Basic error checking.
		*x = table[*x];
}

void inverse_s_box(uint8_t *x)
{
	const uint8_t table[] = { 0x09,
							  0x04,
							  0x0f,
							  0x0a,
							  0x0e,
							  0x01,
							  0x00,
							  0x06,
							  0x0c,
							  0x07,
							  0x03,
							  0x08,
							  0x02,
							  0x0b,
							  0x05,
							  0x0d
							};

	if(*x >= 0x00 && *x <= 0x0F)	// Basic error checking.
		*x = table[*x];
}


// ------------------------ KEY SCHEDULE (128 BIT KEY) ------------------------

/*
**	Description: The sub-key for each of the first 24 rounds are computed.
**	Input: Parameters of the cipher.
**	Output: parameters->sub_key[] is overwritten with the sub-key (i.e. round key)
**	  for the current round. It is also returned to the calling function.
**	Caveats: Initialise cipher parameters using rectangle_init() - applies only
**	  for the very first call to get_round_key().
**	Thread-safe: Yes.
*/
uint16_t* get_round_key(rcipher_params_t parameters)
{
	int i, j;
	uint8_t col_value, j_mask, col_bit, key_bit[4];

	/*
	**	Step: Extracting the sub-key for the current round.
	**	For each of the 4 rows, we extract the rightmost 16 bits.
	**	Total: 4 x 16 = 64 bit sub-key.
	**	This forms the sub-key for the current round.
	*/
	for(i = 0; i < 4; ++i)
		parameters->sub_key[i] = (uint16_t) (parameters->main_key[i] & 0x0000FFFF);

	/*
	**	Step: Applying the S-Box S to the 8 rightmost columns.
	**	For each of the 8 rightmost columns, we first need to construct the column
	**	value, i.e., the hexadecimal value corresponding to the column.
	**	Then, we use the S-Box to jumble up the bits and then write the resultant
	**	hexadecimal value back to the main key.
	*/
	for(j = 0; j < 8; ++j)
	{
		col_value = 0;
		j_mask = 1 << j;

		// Constructing the column value.
		for(i = 0; i < 4; ++i)
		{
			key_bit[i] = (parameters->main_key[i] & j_mask) > 0;
			col_value |= (key_bit[i] << i);
		}

		// Use the S-Box to find the new column value...
		s_box(&col_value);

		// Writing the resultant hexadecimal value back to main_key.
		for(i = 0; i < 4; ++i)
		{
			col_bit = ((col_value & (1 << i)) > 0);

			/*	If the key bit and the col bit do not match, then flip the
			**	main_key bit. */
			parameters->main_key[i] ^= (key_bit[i] ^ col_bit) << j;
		}
	}


	// Step: Applying a 1-round generalized Feistel transformation.
	uint32_t row0 = parameters->main_key[0], row2 = parameters->main_key[2];
	parameters->main_key[0] = CLSH(parameters->main_key[0], 8) ^ parameters->main_key[1];
	parameters->main_key[2] = CLSH(parameters->main_key[2], 16) ^ parameters->main_key[3];
	parameters->main_key[1] = row2;
	parameters->main_key[3] = row0;


	// Step: A 5-bit round constant is XORed with the 5-bit key state.
	// Extracting the lower "5 bit key state"...
	uint8_t lower_5_bits = (uint8_t) (parameters->main_key[0] & 0x0000001F);
	lower_5_bits ^= parameters->row_constant;

	// Turn off lower 5 bits..and append the new lower 5 bits.
	parameters->main_key[0] = (parameters->main_key[0] & 0xFFFFFFE0) | lower_5_bits;


	// Update the row constant.
	rectangle_LFSR(&parameters->row_constant);
	return parameters->sub_key;
}


/*	
**	Description: The key for the 25th(last) round is computed.
**	Input: Parameters of the cipher.
**	Output: parameters->sub_key[] is overwritten with the sub-key (i.e. round key)
**	  for the 25th(last) round.
**	Caveats: None.
**	Thread-safe: Yes.
*/
uint16_t* get_key25(rcipher_params_t parameters)
{
	int i;

	// Extracting the key for the last AddRoundKey().
	for(i = 0; i < 4; ++i)
		parameters->sub_key[i] = (uint16_t) (parameters->main_key[i] & 0x0000FFFF);

	return parameters->sub_key;
}


// ------------------------ ENCRYPTION ------------------------


#define BLOCK_SIZE 8	
/*
**	Represents block size in bytes (and not bits). Also, it is assumed that the
**	block size is a power of 2.	This fact is used to quickly determine whether
**	the size of the plain text is a	multiple of the block size or not (in the
**	encrypt() function). This check is performed using bit arithmetic which will
**	only work if the block size is a power of 2. In case there is a requirement
**	for supporting block sizes which are not a power of 2, then the check (of
**	whether the plain text size is a multiple of block size or not) can be done
**	using the modulo (remainder, %) operator. The rest of the code should work
**	fine; although testing the code after modification is highly recommended.
**	NB: It is also used in the declaration of union state to calculate the size
**	of ints16.
*/							

union state
{
	unsigned char bytes [BLOCK_SIZE];
	uint16_t ints16 [BLOCK_SIZE >> 1];
};

struct string
{
	ssize_t length;
	unsigned char* str;
};

typedef union state* state64_t;
typedef struct string* string_t;


string_t init_string(char* text)
{
	ssize_t i = 0;

	string_t s = malloc(sizeof(struct string));

	if(s == NULL)
	{
		perror("Could not allocate memory in init_string(). File: rectangle.h\nError");
		exit(EXIT_FAILURE);
	}

	s->length = strlen(text) + 1;
	s->str = malloc(s->length);

	if(s->str == NULL)
	{
		perror("Could not allocate memory in init_string(). File: rectangle.h\nError");
		exit(EXIT_FAILURE);
	}

	while(s->str[i] = text[i])
		++i;

	return s;
}

string_t init_string_bytes(char* bytes, ssize_t length)
{
	ssize_t i = 0;

	string_t s = malloc(sizeof(struct string));

	if(s == NULL)
	{
		perror("Could not allocate memory in init_string_bytes(). File: rectangle.h\nError");
		exit(EXIT_FAILURE);
	}

	s->length = length;
	s->str = malloc(length);

	if(s->str == NULL)
	{
		perror("Could not allocate memory in init_string_bytes(). File: rectangle.h\nError");
		exit(EXIT_FAILURE);
	}

	for(; i < length; ++i)
		s->str[i] = bytes[i];

	return s;
}

void destroy_string(string_t string)
{
	if(string != NULL)
	{
		free(string->str);
		free(string);
		string = NULL;
	}
}

// for testing
#define HEX(x) (x > 9 ?('A' + (x - 10)) :('0' + x))

char* encrypt_64bit_block(rcipher_params_t parameters, state64_t plaintext_state)
{
	uint8_t round_no, i, j;
	uint8_t col_j, ptext_bit[4], col_bit;
	uint16_t j_mask;

	// For the first 24 rounds..
	for(round_no = 0; round_no < 24; ++round_no)
	{
		// Step: Generate round key.
		get_round_key(parameters);
	
		// Step: AddRoundKey(STATE, Ki): Simple XOR
		for(i = 0; i < 4; ++i)
			plaintext_state->ints16[i] ^= parameters->sub_key[i];

		// Step: SubColumn(STATE)
		for(j = 0; j < 16; ++j)
		{
			col_j = 0;
			j_mask = 1 << j;

			for(i = 0; i < 4; ++i)
			{
				ptext_bit[i] = (plaintext_state->ints16[i] & j_mask) > 0;
				col_j |= ptext_bit[i] << i;
			}

			s_box(&col_j);

			for(i = 0; i < 4; ++i)
			{
				col_bit = (col_j & (1 << i)) > 0;
				plaintext_state->ints16[i] ^= (ptext_bit[i] ^ col_bit) << j;
			}
		}

		// Step: ShiftRow(STATE)
		plaintext_state->ints16[1] = CLSH(plaintext_state->ints16[1], 1);
		plaintext_state->ints16[2] = CLSH(plaintext_state->ints16[2], 12);
		plaintext_state->ints16[3] = CLSH(plaintext_state->ints16[3], 13);
	}

	// Step: AddRoundKey(STATE, K25)
	get_key25(parameters);

	for(i = 0; i < 4; ++i)
		plaintext_state->ints16[i] ^= parameters->sub_key[i];

	return plaintext_state->bytes;
}


string_t encrypt(rcipher_params_t parameters, string_t ptext)
{
	string_t ctext = malloc(sizeof(struct string));

	if(ctext == NULL)
	{
		perror("Could not allocate memory in encrypt(). File: rectangle.h\nError");
		exit(EXIT_FAILURE);
	}

	rcipher_params_t params = rectangle_init_copy(parameters);

	ssize_t padded_len, ptext_pos, i;
	char pad_byte;
	union state block;

	if((ptext->length & (BLOCK_SIZE - 1)) == 0)		// string length is a multiple of BLOCK_SIZE
		padded_len = ptext->length + BLOCK_SIZE;
	else
	{
		padded_len = ~(BLOCK_SIZE - 1);
		padded_len = (ptext->length & padded_len) + BLOCK_SIZE;
		// For this bit arithmetic to work, padded_len and ptext->length should be of the exact same data type.
	}

	ctext->str = malloc(padded_len);

	if(ctext->str == NULL)
	{
		perror("Could not allocate memory in encrypt(). File: rectangle.h\nError");
		free(ctext);
		exit(EXIT_FAILURE);
	}

	ctext->length = padded_len;
	pad_byte = padded_len - ptext->length;
	
	for(ptext_pos = 0; ptext_pos < padded_len;)
	{
		for(i = 0; i < BLOCK_SIZE && ptext_pos < ptext->length; ++i, ++ptext_pos)
			block.bytes[i] = ptext->str[ptext_pos];

		for(; i < BLOCK_SIZE; ++i, ++ptext_pos)
			block.bytes[i] = pad_byte;

		encrypt_64bit_block(params, &block);

		for(i = 0; i < BLOCK_SIZE; ++i)
			ctext->str[ptext_pos - BLOCK_SIZE + i] = block.bytes[i];

		rectangle_params_copy(params, parameters);
	}

	rectangle_destroy(params);
	return ctext;
}


// ------------------------ DECRYPTION ------------------------

struct round_key
{
	uint16_t key[4];
} round_keys[25];

typedef struct round_key* round_key_t;


round_key_t store_round_keys(rcipher_params_t parameters, round_key_t keys)
{
	uint8_t i, j;
	rcipher_params_t params = rectangle_init_copy(parameters);

	for(i = 0; i < 25; ++i)
	{
		if(i != 24)
			get_round_key(params);
		else
			get_key25(params);

		for(j = 0; j < 4; ++j)
			keys[i].key[j] = params->sub_key[j];
	}

	rectangle_destroy(params);
	return keys;
}


char* decrypt_64bit_block(rcipher_params_t parameters, state64_t ciphertext_state)
{
	uint8_t round_no, i, j;
	uint8_t col_j, ctext_bit[4], col_bit;
	uint16_t j_mask;

	store_round_keys(parameters, round_keys);

	for(round_no = 24; round_no > 0; --round_no)
	{
		// Step: AddRoundKey(STATE, Ki): Simple XOR
		for(i = 0; i < 4; ++i)
			ciphertext_state->ints16[i] ^= round_keys[round_no].key[i];

		// Step: Inverse ShiftRow(STATE)
		ciphertext_state->ints16[1] = CLSH(ciphertext_state->ints16[1], 15);
		ciphertext_state->ints16[2] = CLSH(ciphertext_state->ints16[2], 4);
		ciphertext_state->ints16[3] = CLSH(ciphertext_state->ints16[3], 3);

		// Step: Inverse SubColumn(STATE)
		for(j = 0; j < 16; ++j)
		{
			col_j = 0;
			j_mask = 1 << j;

			for(i = 0; i < 4; ++i)
			{
				ctext_bit[i] = (ciphertext_state->ints16[i] & j_mask) > 0;
				col_j |= ctext_bit[i] << i;
			}

			inverse_s_box(&col_j);

			for(i = 0; i < 4; ++i)
			{
				col_bit = (col_j & (1 << i)) > 0;
				ciphertext_state->ints16[i] ^= (ctext_bit[i] ^ col_bit) << j;
			}
		}
	}

	// Step: AddRoundKey(STATE, K0)
	for(i = 0; i < 4; ++i)
			ciphertext_state->ints16[i] ^= round_keys[round_no].key[i];

	return ciphertext_state->bytes;
}

string_t decrypt(rcipher_params_t parameters, string_t ctext)
{
	string_t ptext = malloc(sizeof(struct string));

	if(ptext == NULL)
	{
		perror("Could not allocate memory in decrypt(). File: rectangle.h\nError");
		exit(EXIT_FAILURE);
	}

	ptext->length = ctext->length;
	ptext->str = malloc(ctext->length);

	if(ptext->str == NULL)
	{
		perror("Could not allocate memory in decrypt(). File: rectangle.h\nError");
		free(ptext);
		exit(EXIT_FAILURE);
	}

	union state block;
	ssize_t ctext_pos, i;
	char pad_byte;

	for(ctext_pos = 0; ctext_pos < ctext->length;)
	{
		for(i = 0; i < BLOCK_SIZE; ++i, ++ctext_pos)
			block.bytes[i] = ctext->str[ctext_pos];

		decrypt_64bit_block(parameters, &block);

		for(i = 0; i < BLOCK_SIZE; ++i)
			ptext->str[ctext_pos - BLOCK_SIZE + i] = block.bytes[i];
	}

	pad_byte = ptext->str[ptext->length - 1];
	i = ptext->length - pad_byte;
	if(i < 0)
		i = 0;
	
	for(; i < ptext->length; ++i)
		if(ptext->str[i] != pad_byte)
		{
			errno = EBADMSG;
			perror("Error while decrypting! Possibly invalid key.\nError");
			free(ptext->str);
			free(ptext);
			exit(EXIT_FAILURE);
		}

	ptext->length -= pad_byte;

	return ptext;
}

#endif
