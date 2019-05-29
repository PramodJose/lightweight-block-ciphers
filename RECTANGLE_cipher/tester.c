#include <stdio.h>
#include <string.h>
#include <time.h>
#include "rectangle.h"

#define HEX(x) (x > 9 ?('A' + (x - 10)) :('0' + x))

typedef enum {start_timer, stop_timer} timer_state;

void print_info();
void print_in_hex(string_t);
void timer(timer_state, char*);


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
	string_t plaintext, ciphertext, decrypted_ptext;

	// Input your plaintext here..
	// ..either as a byte array..
	char ptext[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	plaintext = init_string_bytes(ptext, sizeof(ptext));

	// ..or as a string.
	/*char *ptext = "The author of this piece of code is Pramod.";
	plaintext = init_string(ptext);*/
	
	print_info();
	printf("Plaintext in hex:\t");
	print_in_hex(plaintext);

	timer(start_timer, NULL);
	ciphertext = encrypt(cipher_params, plaintext);
	timer(stop_timer, "Encryption");

	printf("Ciphertext in hex:\t");
	print_in_hex(ciphertext);

	timer(start_timer, NULL);
	decrypted_ptext = decrypt(cipher_params, ciphertext);
	timer(stop_timer, "Decryption");

	printf("Decrypted ptext in hex:\t");
	print_in_hex(decrypted_ptext);

	destroy_string(decrypted_ptext);
	destroy_string(plaintext);
	destroy_string(ciphertext);
	rectangle_destroy(cipher_params);
}


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

void timer(timer_state state, char* process_name)
{
	static struct timespec start = {0, 0}, end = {0, 0};

	if(state == start_timer)
		clock_gettime(CLOCK_MONOTONIC, &start);
	else
	{
		long int seconds_elapsed, ns_elapsed;
		clock_gettime(CLOCK_MONOTONIC, &end);
		
		seconds_elapsed = end.tv_sec - start.tv_sec;
		ns_elapsed = end.tv_nsec - start.tv_nsec;

		if(end.tv_nsec < start.tv_nsec)
		{
			--seconds_elapsed;
			ns_elapsed += 1000000000;  
		}

		printf("%s finished in %ld second(s) and %ld nanoseconds.\n\n", process_name, seconds_elapsed, ns_elapsed);
	}
}
