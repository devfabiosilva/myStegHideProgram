/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2018
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

// for main.c
#define SUCCESS (int) 0
#define ERR_MISSING_FILE (int) -1
#define ERR_TOO_MANY_ARGS (int) -2
#define ERR_FEW_ARGS (int) -3
#define ERR_SAME_FILENAME (int) -100
#define ERR_FILE_NAME_EXCEEDS_FIELD_NAME (int) -61
#define ERR_EMPTY_FILENAME (int) -85
#define ERR_FILE_NOT_FOUND (int) -4
#define ERR_HIDDEN_FILE_NOT_EXISTS (int) -5
#define ERR_UNABLE_TO_OPEN_DEST_FILE (int) -6
#define ERR_IN_FUNCTION (int) -7
#define ERR_PASSWORD_DOES_NOT_MATCH (int) -42
#define ERR_BAD_MAGIG_NUMBER (int) -19

//for prompt.h

#define ERR_MAX_PASS_LENGTH (int) 184
#define ERR_PASS_NULL (int) 180
#define ERR_UNABLE_TO_READ_STDIN (int) 192
#define ERR_UNABLE_TO_RESTORE_CONSOLE (int) 0x00501100

//for fsha256.h

#define ERR_GET_PRIVATE_KEY (int) 71
#define ERR_GENERATING_PRIVATE_KEY (int) 70
#define ERR_WRITING_FILE (int) 5

// for fstruct.h

#define ERR_LESS_THAN_SZ_MALLOC (int) 17
#define ERR_SEEK_FILE_POSITION (int) 11
#define ERR_READING_FILE (int) 19
#define ERR_INVALID_MAGIC_NUMBER (int) 43
#define ERR_FILE_ALREADY_EXISTS (int) 27
#define ERR_SHA256_CHECKSUM_FAILED (int) 10001
#define ERR_OVERHEAD_FILE (int) 6000
#define ERR_UNKNOWN_CYPHER_MODE (int) 3000
#define ERR_UNABLE_CREATE_FILE (int) 28
#define ERR_UNABLE_OPENING_FILE (int) 8

#define MSG_UNKNOWN_FILE_CMD_ERR (int) 128

