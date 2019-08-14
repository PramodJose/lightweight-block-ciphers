#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include "rectangle_cbc.h"

#define ENCRYPT_MODE 1
#define DECRYPT_MODE 2

typedef enum {start_timer, stop_timer} timer_state;

void parse_hex(char* dest, char* src, size_t size)
{
	int i, j = size - 1;
	for(i = 0; src[i] != '\0'; ++i);

	// Go to last byte.
	if(i > 1)
		i -= 2;
	else
		i = 0;

	for(; j >= 0; --j, i -= 2)
		if(i >= 0 && src[i] != '0' && src[i] != 'x' && src[i] != 'X')
			sscanf(src + i, "%2hhx", &dest[j]);
		else
			dest[j] = 0;
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

		printf("%s finished in %ld second(s) and %09ld nanoseconds.\n\n", process_name, seconds_elapsed, ns_elapsed);
	}
}

int main(int argc, char* argv[])
{
	extern char* optarg;
	int option;
	char mode = 0;
	FILE *in_stream = NULL, *out_stream = NULL;
	uint8_t IV[BLOCK_SIZE], key[MAIN_KEY_SIZE];
	int8_t error_flag = 0, iv_set = 0, key_set = 0;

	//				mode, IV, key, input stream, output stream
	while((option = getopt(argc, argv, "edv:k:i:o:")) != -1)
	{
		switch(option)
		{
			case 'e':
				if(mode)
				{
					printf("The mode can either be encrypt or decrypt - not both.\n");
					error_flag = 1;
				}
				else
					mode = ENCRYPT_MODE;
				break;
			case 'd':
				if(mode)
				{
					printf("The mode can either be encrypt or decrypt - not both.\n");
					error_flag = 1;
				}
				else
					mode = DECRYPT_MODE;
				break;
			case 'v':
				parse_hex(IV, optarg, BLOCK_SIZE);
				iv_set = 1;
				break;
			case 'k':
				parse_hex(key, optarg, MAIN_KEY_SIZE);
				key_set = 1;
				break;
			case 'i':
				if(optarg[0] == '-' && optarg[1] == '\0')
					in_stream = stdin;
				else
				{
					in_stream = fopen(optarg, "r");
					if(in_stream == NULL)
					{
						printf("Could not open file %s for reading the plaintext.\n", optarg);
						error_flag = 1;
					}
				}
				break;
			case 'o':
				if(optarg[0] == '-' && optarg[1] == '\0')
					out_stream = stdout;
				else
				{
					out_stream = fopen(optarg, "w");
					if(out_stream == NULL)
					{
						printf("Could not open file %s for writing the ciphertext.\n", optarg);
						error_flag = 1;
					}
				}
				break;
			case ':':
				printf("This option needs an argument.\n");
				error_flag = 1;
				break;
			case '?':
			case 'h':
				printf("Need to print usage here.\n");
				break;
		}
	}

	if(mode == 0)
	{
		printf("You need to specify the mode!\n");
		error_flag = 1;
	}

	if(!iv_set)
	{
		printf("You need to specify the 64 bit IV.\n");
		error_flag = 1;
	}

	if(!key_set)
	{
		printf("You need to specify the 80 bit key.\n");
		error_flag = 1;
	}

	if(error_flag)
	{
		if(in_stream != NULL)
			fclose(in_stream);
		if(out_stream != NULL)
			fclose(out_stream);

		return -1;
	}

	if(in_stream == NULL)
		in_stream = stdin;
	if(out_stream == NULL)
		out_stream = stdout;

	timer(start_timer, NULL);
	if(mode == ENCRYPT_MODE)
		encrypt(IV, key, in_stream, out_stream);
	else if(mode == DECRYPT_MODE)
		decrypt(IV, key, out_stream, in_stream);
	timer(stop_timer, ((mode == ENCRYPT_MODE)? "Encryption" : ((mode == DECRYPT_MODE) ? "Decryption" : "NULL")));

	fclose(in_stream);
	fclose(out_stream);
	return 0;
}
