/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2018
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

 // for MAIN file.
 
#define BUF_FILE_SZ 1024*AES_BLK_SZ

#define FILE_AES_BLK_SZ BUF_FILE_SZ

static unsigned char DEST_FILE_SHA256SUM[SHA256_DIGEST_LENGTH];

#define MAX_STR_LEN 512

#ifdef WIN
	#define FS '\\'
#else
	#define FS '/'
#endif

#define FILE_ALLOC_SZ 256

#define CMD_ADD_STEGED_FILE "add"
#define CMD_ADD_STEGED_FILE_WITH_PASSWORD "add-with-password"
#define CMD_EXTRACT_STEGED_FILE "extract"
#define CMD_INFO_STEGED_FILE "info"
#define CMD_USAGE "usage"
#define CMD_VERSION "version"

// for fencrypt.h

#ifndef TEST
	#define AES_BLK_SZ 2*AES_BLOCK_SIZE
#endif

#define PBKDF2_ITER 262144*2*2

// for festruct.h

#define MAGIC "\011fpsstg"
#define MAGIC_SZ (int) 7
#define AUTHOR_SZ (int) 48
#define AUTHOR_EMAIL_SZ (int) 32
#define FILENAME_SZ (int)(65+3)

#define C_AUTHOR "Fábio Pereira da Silva 2018 CC"
#define C_AUTHOR_EMAIL "fabioegel@gmail.com"
#define VERSION_NUM (int)0x1A6CF23F
#define VERSION_NUM2 (int)0x0EB1FAF5
#define HIDDEN_TYPE_PLAINTEXT (int)0xFFFFFFFF
#define HIDDEN_TYPE_AES256_SALT (int)0xAAAAAAAA
#define MAJOR_VERSION (int)1
#define MINOR_VERSION (int)22

#define SZ_MALLOC (size_t)(sizeof(struct magic_number_t)+sizeof(struct structure_t))

// for prompt.h
#define MAX_PASS_LENGTH 128

