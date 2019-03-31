/*
**	AUTHOR:	Pramod Jose
**	GITHUB:	github.com/PramodJose
**	DATE:	29 March 2019
*/

#ifndef _RECTANGLE_CIPHER_H
#define _RECTANGLE_CIPHER_H 1

/*	Definition for circular left shift.
**	Parameter 1: num is the integer variable you want to shift
**	Parameter 2: shift is the number of places you want to shift "num" by.
**	Note: This definition has been adapted from en.wikipedia.org/wiki/Bitwise_operation#Circular_shifts
**
**	Example:
**	uint8_t val = 0x97;
**	val	= CLSH(val, 3);
*/
#define CLSH(num, shift) ((num << shift) | (num >> (-shift & (sizeof(num) * 8 - 1))))

#include <stdint.h>

/*
**	Description: Defines/Emulates the LFSR used in the RECTANGLE cipher.
**	  Computes the next row constant given the current row constant.
**	Input: Address of the variable which contains the current row constant.
**	Output: Modifies the variable in place. After the completion of this function,
**	  the row constant variable would contain the new row constant.
**	Caveats: The row constant should be initialised to 0x01 (the very first row
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

		// sticking rc0 at the end...
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


// ------------------------ KEY SCHEDULE (128 BIT KEY) ------------------------

void get_round_key(uint32_t main_key[], uint16_t sub_key[], uint8_t *row_constant)
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
		sub_key[i] = (uint16_t) (main_key[i] & 0x0000FFFF);


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
			key_bit[i] = (main_key[i] & j_mask) > 0;
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
			main_key[i] ^= (key_bit[i] ^ col_bit) << j;
		}
	}


	// Step: Applying a 1-round generalized Feistel transformation.
	uint32_t row0 = main_key[0], row2 = main_key[2];
	main_key[0] = CLSH(main_key[0], 8) ^ main_key[1];
	main_key[2] = CLSH(main_key[2], 16) ^ main_key[3];
	main_key[1] = row2;
	main_key[3] = row0;


	// Step: A 5-bit round constant is XORed with the 5-bit key state.
	// Extracting the lower "5 bit key state"...
	uint8_t lower_5_bits = (uint8_t) (main_key[0] & 0x0000001F);
	lower_5_bits ^= *row_constant;

	// Turn off lower 5 bits..and append the new lower 5 bits.
	main_key[0] = (main_key[0] & 0xFFFFFFE0) | lower_5_bits;


	// Update the row constant.
	rectangle_LFSR(row_constant);
}

void get_k25(uint32_t main_key[], uint16_t sub_key[])
{
	int i;
	// Extracting the key for the last AddRoundKey().
	for(i = 0; i < 4; ++i)
		sub_key[i] = (uint16_t) (main_key[i] & 0x0000FFFF);
}




#endif
