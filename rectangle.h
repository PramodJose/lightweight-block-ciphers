/*
**	AUTHOR:	Pramod Jose
**	GITHUB:	github.com/PramodJose
**	DATE:	29 -03 -2019
*/

#ifndef _RECTANGLE_CIPHER_H
#define _RECTANGLE_CIPHER_H 1

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




#endif
