/*
 * main.c
 * This file is part of fstg
 *
 * Copyright (C) 2018 - Fábio Pereira da Silva
 *
 *  fstg is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 *  fstg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with  fstg. If not, see <http://www.gnu.org/licenses/>.
 */

//Aug 21 Thu 15:35:19 -03 2018
//Ter Ago 21 15:35:19 -03 2018

#include <time.h>
#include <stddef.h>
#include <stdlib.h>
#include <termios.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "fdefconfig.h"
#include "ferrno.h"
#include "fstdmsg.h"

#include "prompt.h"
#include "fencrypt.h"
#include "fstruct.h"
#include "fsha256.h"
#include "ffileutil.h"

int main(int argc, char **argv)
{
	int err=SUCCESS;
	char pass1[MAX_PASS_LENGTH];
	char pass2[MAX_PASS_LENGTH];
	time_t current_time = time(NULL);

	char calc_hash[2*SHA256_DIGEST_LENGTH+1];
	struct structure_t estr_tmp;
	struct magic_number_t nm_tmp;

	char *dest_file_name = malloc(FILE_ALLOC_SZ);

	if (!dest_file_name) return ENOMEM;

	char *stg_file_name = malloc(FILE_ALLOC_SZ);

	if (!stg_file_name)
	{
		err=ENOMEM;
		goto MAIN_EXIT1;	
	}

	char *stg_info_file_name=malloc(FILE_ALLOC_SZ);

	if (!stg_info_file_name)
	{
		err=ENOMEM;
		goto MAIN_EXIT2;
	}

	char *tmp = malloc(FILE_ALLOC_SZ);

	if (!tmp)
	{
		err=ENOMEM;
		goto MAIN_EXIT3;
	}

	FILE *dest_file;

	FILE *stg_file;

#ifdef DEBUG
	printf("\nTime: %s\n",ctime(&current_time));
#endif

	memset(&estr_tmp,0,sizeof(estr_tmp));

	start_magic_number(&magic_number);

	if (argc>1)
	{
		//start_magic_number(&magic_number);

		if (!strcmp(argv[1], CMD_ADD_STEGED_FILE))
		{

			if (argc<3)
			{
				printf(MSG_MISSING_FILE);
				err=ERR_MISSING_FILE;
				goto MAIN_EXIT4;
			}

			if (argc>4)
			{
				printf(MSG_MANY_ARG,argv[argc-1]);
				err=ERR_TOO_MANY_ARGS;
				goto MAIN_EXIT4;
			}
			if (argc<4)
			{
				printf(MSG_FEW_ARG);
				err=ERR_FEW_ARGS;
				goto MAIN_EXIT4;
			}

			strcpy(stg_file_name, argv[3]);
			strcpy(dest_file_name, argv[2]);

			if (!strcmp(stg_file_name, dest_file_name))
			{
				err=ERR_SAME_FILENAME;
				printf(DEF_MSG_02, err);
				goto MAIN_EXIT4;
			}

			if (strlen(trunc(strcpy(tmp,is_filename(stg_file_name))))>(sizeof(estr_tmp.filename)-1))
			{
				printf(STG_FILE_NAME_MAX, tmp, (unsigned long int)(sizeof(estr_tmp.filename)-1));
				err=ERR_FILE_NAME_EXCEEDS_FIELD_NAME;
				goto MAIN_EXIT4;
			}

			// Added to ver 1.1
			if (tmp[0]=='\0')
			{
				printf(STG_FILE_NAME_NULL);
				err=ERR_EMPTY_FILENAME;
				goto MAIN_EXIT4;
			}
			/////

			strcpy(estr_tmp.filename, tmp);

#ifdef DEBUG
			printf("\nTemp file = %s\n", tmp);
			printf("\nFILE stg_file = %s\n", stg_file);
#endif


			if (file_not_exists(dest_file_name))
			{
				printf(MSG_FILE_NOT_FOUND, dest_file_name);
				err=ERR_FILE_NOT_FOUND;
				goto MAIN_EXIT4;
			}

			stg_file=fopen(stg_file_name,"rb");

			if (!stg_file)
			{
				printf(MSG_HIDDEN_FILE_NOT_EXISTS, stg_file_name);
				err=ERR_HIDDEN_FILE_NOT_EXISTS;
				goto MAIN_EXIT4;
			}

			dest_file=fopen(dest_file_name, "a+b");

			if (!dest_file)
			{
				printf(MSG_UNABLE_TO_OPEN_DEST_FILE, dest_file_name, stg_file_name);
				err=ERR_UNABLE_TO_OPEN_DEST_FILE;
				goto MAIN_EXIT5;
			}


			fseek(dest_file, 0, SEEK_END);
			//estr_tmp.skip=ftell(dest_file); // Deleted version 1.2
// Added version 1.2
			if ((estr_tmp.skip=(uint64_t)ftell(dest_file))<10*SZ_MALLOC)
			{
				printf(MSG_DEST_FILE_TOO_SMALL, (unsigned long int) 10*SZ_MALLOC);
				err=ERR_LESS_THAN_SZ_MALLOC;
				goto MAIN_EXIT6;
			}

			//fseek(fl_r, 0, SEEK_END);

			//size_t flSize=ftell(fl_r);

			//if (flSize<10*SZ_MALLOC) return ERR_LESS_THAN_SZ_MALLOC;
// End
			printf(MSG_WARNING_ADDING_HIDDEN_FILE, stg_file_name, dest_file_name);
			if (err=insert_steg_file(stg_file, dest_file, 0,"",&estr_tmp.SHA256SUM))
			{
				printf(MSG_ERR_IN_FUNCTION, err);
				err=ERR_IN_FUNCTION;
				goto MAIN_EXIT6;
			}

			fseek(stg_file, 0, SEEK_END);

			estr_tmp.size=(uint64_t)ftell(stg_file);
			
			estr_tmp.timestamp=current_time;
			estr_tmp.hidden_type=HIDDEN_TYPE_PLAINTEXT;
			start_struct(&estr_tmp);

			if (err=write_structure(dest_file))
			{
				printf(MSG_ERR_NO, err);
				goto MAIN_EXIT6;
			}

			printf(MSG_FILE_ADDED_SUCCESSFULLY, stg_file_name, dest_file_name, ctime(&current_time));

			goto MAIN_EXIT6;

		}

		if (!strcmp(argv[1], CMD_ADD_STEGED_FILE_WITH_PASSWORD))
		{

			if (argc<3)
			{
				printf(MSG_MISSING_FILE);
				err=ERR_MISSING_FILE;
				goto MAIN_EXIT4;
			}
			if (argc>4)
			{
				printf(MSG_MANY_ARG,argv[argc-1]);
				err=ERR_TOO_MANY_ARGS;
				goto MAIN_EXIT4;

			}
			if (argc<4)
			{
				printf(MSG_FEW_ARG);
				err=ERR_FEW_ARGS;
				goto MAIN_EXIT4;
			}

			strcpy(stg_file_name, argv[3]);
			strcpy(dest_file_name, argv[2]);

			if (!strcmp(stg_file_name, dest_file_name))
			{
				printf(DEF_MSG_02, err);
				err=ERR_SAME_FILENAME;
				goto MAIN_EXIT4;
			}

			if (strlen(trunc(strcpy(tmp,is_filename(stg_file_name))))>(sizeof(estr_tmp.filename)-1))
			{
				printf(STG_FILE_NAME_MAX, tmp, (unsigned long int)(sizeof(estr_tmp.filename)-1));
				err=ERR_FILE_NAME_EXCEEDS_FIELD_NAME;
				goto MAIN_EXIT4;
			}

			// Added to ver 1.1
			if (tmp[0]=='\0')
			{
				printf(STG_FILE_NAME_NULL);
				err=ERR_EMPTY_FILENAME;
				goto MAIN_EXIT4;
			}
			/////

			strcpy(estr_tmp.filename, tmp);

#ifdef DEBUG
			printf("\nFile tmp = %s\n", tmp);
			printf("\nFILE stg_file = %s\n", stg_file);
#endif

			if (file_not_exists(dest_file_name))
			{
				printf(MSG_FILE_NOT_FOUND, dest_file_name);
				err=ERR_FILE_NOT_FOUND;
				goto MAIN_EXIT4;
			}

			stg_file=fopen(stg_file_name,"rb");

			if (!stg_file)
			{
				printf(MSG_FILE_TO_BE_ENCRYPTED_NOT_EXISTS, stg_file_name);
				err=ERR_HIDDEN_FILE_NOT_EXISTS;
				goto MAIN_EXIT4;
			}

			dest_file=fopen(dest_file_name, "r+");

			if (!dest_file)
			{
				printf(MSG_UNABLE_TO_OPEN_DEST_FILE_ENCRYPTED, dest_file_name, stg_file_name);
				err=ERR_UNABLE_TO_OPEN_DEST_FILE;
				goto MAIN_EXIT5;
			}

			sha256_file(dest_file,DEST_FILE_SHA256SUM);
			//estr_tmp.skip=ftell(dest_file); // removed from 1.2 Version
// Added version 1.2
			if ((estr_tmp.skip=(uint64_t)ftell(dest_file))<10*SZ_MALLOC)
			{
				printf(MSG_DEST_FILE_TOO_SMALL, (unsigned long int) 10*SZ_MALLOC);
				err=ERR_LESS_THAN_SZ_MALLOC;
				goto MAIN_EXIT6;
			}
// End
#ifdef DEBUG
			sha256_hash_string(DEST_FILE_SHA256SUM,tmp);
			printf("\nGetting HASH of the main file %s\n", tmp); //Obtendo o HASH do arquivo principal
			printf("\nGetting file size %d\n", estr_tmp.skip); //Obtendo o tamanho do arquivo
#endif


			memset(pass1,0,sizeof(pass1));
			memset(pass2,0,sizeof(pass2));

			printf(MSG_TYPE_YOUR_PASSWORD);

			if (err=get_passwd(pass1))
			{
				printf(MSG_SOMETHING_WENT_WRONG, err);
				goto MAIN_EXIT7;
			}

			printf(MSG_RETYPE_YOUR_PASSWORD);

			if (err=get_passwd(pass2))
			{
				printf(MSG_ERR_WHEN_MACTHING_PASS, err);
				goto MAIN_EXIT8;
			}

			if (memcmp(pass1,pass2,sizeof(pass1)))
			{
				memset(pass1,0,sizeof(pass1));
				memset(pass2,0,sizeof(pass2));
				printf(MSG_PASS_DOES_NOT_MATCH);
				err=ERR_PASSWORD_DOES_NOT_MATCH;
				goto MAIN_EXIT8;
			}
			memset(pass2,0,sizeof(pass2));
			printf(MSG_ADDING_AND_ENCRYPTING, stg_file_name, dest_file_name);


			if (err=insert_steg_file(stg_file, dest_file, 1,pass1,&estr_tmp.SHA256SUM))
			{
				printf(MSG_ERR_INSERT_ENCRYPTED_FILE, stg_file_name, err);
				goto MAIN_EXIT8;
			}

			memset(pass1,0,sizeof(pass1));

			fseek(stg_file, 0, SEEK_END);

			estr_tmp.size=(uint64_t)ftell(stg_file);

			estr_tmp.timestamp=current_time;
			estr_tmp.hidden_type=HIDDEN_TYPE_AES256_SALT;
			estr_tmp.overhead=structure.overhead;
			start_struct(&estr_tmp);

			if (err=write_structure(dest_file))
			{
				printf(MSG_ERR_NO,err);
				goto MAIN_EXIT8;
			}

			printf(MSG_FILE_ADDED_SUCCESSFULLY, stg_file_name, dest_file_name, ctime(&current_time));

			goto MAIN_EXIT8;
		}

		if (!strcmp(argv[1],CMD_EXTRACT_STEGED_FILE))
		{

			if (argc>3)
			{
				printf(MSG_MANY_ARG_EXTRACT_FILE, argv[argc-1]);
				err=ERR_TOO_MANY_ARGS;
				goto MAIN_EXIT4;
			}

			if (argc<3)
			{
				printf(MSG_FEW_ARG_EXTRACT_FILE);
				err=ERR_FEW_ARGS;
				goto MAIN_EXIT4;
			}

			strcpy(dest_file_name, argv[2]);

			if (err=extract_stg_file(dest_file_name,&nm_tmp,&estr_tmp,calc_hash))
				printf(MSG_ERR_WHEN_EXTRACTING_FILE, err);
			else
			{
				sha256_hash_string(calc_hash, tmp);
				printf(MSG_FILE_SUCCESSFUL_EXTRACTED, estr_tmp.filename, tmp);
			}

			goto MAIN_EXIT4;
		}

		if (!strcmp(argv[1], CMD_INFO_STEGED_FILE))
		{

			if (argc>3)
			{
				printf(MSG_MANY_ARG_INFO, argv[argc-1]);
				err=ERR_TOO_MANY_ARGS;
				goto MAIN_EXIT4;
			}

			if (argc<3)
			{
				printf(MSG_FEW_ARG_INFO);
				err=ERR_FEW_ARGS;
				goto MAIN_EXIT4;
			}

			strcpy(dest_file_name, argv[2]);

			if (file_not_exists(dest_file_name))
			{
				printf(MSG_FILE_NOT_FOUND, dest_file_name);
				err=ERR_FILE_NOT_FOUND;
				goto MAIN_EXIT4;
			}

			if (err=read_structure(dest_file_name, &nm_tmp, &estr_tmp))
			{
				printf(MSG_ERR_WHEN_READING_STRUCTURE,err, dest_file_name);
				goto MAIN_EXIT4;
			}

			if (memcmp(&nm_tmp, &magic_number, sizeof(nm_tmp)-2*sizeof(int)))
			{
				err=ERR_BAD_MAGIG_NUMBER;
				printf(MSG_MAGIC_NUMBER_ERROR, err, dest_file_name);

				goto MAIN_EXIT4;
			}
			printf(MSG_INFO_FILE_NAME,estr_tmp.filename);
			printf(MSG_FILE_SZ_IN_BYTES, (unsigned long int) estr_tmp.size);
			printf(MSG_INSERTED_FILE_DATE, ctime(&estr_tmp.timestamp));
			(estr_tmp.hidden_type^HIDDEN_TYPE_AES256_SALT)?(estr_tmp.hidden_type^HIDDEN_TYPE_PLAINTEXT)?strcpy(tmp, MSG_ERR_FILE_UNKNOWN_OR_CORRUPTED):strcpy(tmp,NO):strcpy(tmp,YES);
			printf(MSG_INFO_FILE_ENCRYPTED,tmp);
			sha256_hash_string(estr_tmp.SHA256SUM, calc_hash);
			printf(MSG_INFO_HASH256_FILE, calc_hash);

			goto MAIN_EXIT4;
		}

		printf(LICENSE, magic_number.maj_ver^VERSION_NUM, magic_number.min_ver^VERSION_NUM2);

		if (!strcmp(argv[1],CMD_USAGE))
		{
			printf(DEF_MSG);
			if (argc>2)
			{
				printf(MSG_MANY_ARG,argv[argc-1]);
				err=ERR_TOO_MANY_ARGS;
				goto MAIN_EXIT4;

			}
			goto MAIN_EXIT4;
		}

		if (!strcmp(argv[1],CMD_VERSION))
		{
			if (argc>2)
			{
				printf(MSG_MANY_ARG,argv[argc-1]);
				err=ERR_TOO_MANY_ARGS;
				goto MAIN_EXIT4;

			}
			//printf(MSG_VERSION, magic_number.maj_ver^VERSION_NUM, magic_number.min_ver^VERSION_NUM2);
			goto MAIN_EXIT4;
		}

		printf(MSG_UNKNOWN_FILE_CMD, argv[1]);
		err=MSG_UNKNOWN_FILE_CMD_ERR;
		goto MAIN_EXIT4;

	}

	printf(LICENSE, magic_number.maj_ver^VERSION_NUM, magic_number.min_ver^VERSION_NUM2);
	printf(DEF_MSG);

	goto MAIN_EXIT4;

MAIN_EXIT8:
	memset(pass2,0,sizeof(pass2));
MAIN_EXIT7:
	memset(pass1,0,sizeof(pass1));
MAIN_EXIT6:
	fclose(dest_file);
MAIN_EXIT5:
	fclose(stg_file);
MAIN_EXIT4:
	free(tmp);
MAIN_EXIT3:
	free(stg_info_file_name);
MAIN_EXIT2:
	free(stg_file_name);
MAIN_EXIT1:
	free(dest_file_name);
	(err)?printf(MSG_ERR_FINAL, err):printf(MSG_SUCCESS_FINAL);
	return err;
}

