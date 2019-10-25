/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2018
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

struct magic_number_t
{
	char magic[MAGIC_SZ];
	char author[AUTHOR_SZ];
	char author_email[AUTHOR_EMAIL_SZ];
	int maj_ver;
	int min_ver;

};

struct structure_t
{
	time_t timestamp;
	uint64_t skip; // Tamanho do arquivo hospedeiro
	uint64_t size; // Tamanho do arquivo escondido
	uint64_t overhead; // Tamanho > size. Usado na criptografia
	int hidden_type;
	char filename[FILENAME_SZ];
	unsigned char SHA256SUM[SHA256_DIGEST_LENGTH];
};

static struct structure_t structure;
static struct magic_number_t magic_number;

void start_magic_number(struct magic_number_t *nm)
{
	memset(nm, 0, sizeof(struct magic_number_t));
	memcpy(nm->magic, MAGIC, MAGIC_SZ);
	nm->maj_ver=MAJOR_VERSION^VERSION_NUM;
	nm->min_ver=MINOR_VERSION^VERSION_NUM2;

	memcpy(nm->author, C_AUTHOR, sizeof(C_AUTHOR));
	memcpy(nm->author_email, C_AUTHOR_EMAIL, sizeof(C_AUTHOR_EMAIL));
}

void start_struct(struct structure_t *est)
{
	memcpy(&structure, est, sizeof(structure));
}

int write_structure(FILE *fl_a)
{

	if (fwrite(&magic_number,1, sizeof(magic_number),fl_a)^sizeof(magic_number))
	{
#ifdef DEBUG
		printf("\nError on writing magic number\n"); //Erro ao gravar número mágico
#endif
		return ERR_WRITING_FILE;
	}
#ifdef DEBUG
	else
		printf("\nWriting magic number\n"); //Gravando número mágico
#endif

	if (fwrite(&structure,1,sizeof(structure), fl_a)^sizeof(structure))
	{
#ifdef DEBUG
		printf("\nError on writing estruct\n"); //Erro ao gravar estrutura
#endif
		return ERR_WRITING_FILE;
	}
#ifdef DEBUG
	else
		printf("\nWriting structure.\nDone\n");//Gravando estrutura
#endif

	return SUCCESS;
}

int get_stg_info(FILE *fl_r, struct magic_number_t *nm, struct structure_t *est, unsigned char *buf_a)
{
	fseek(fl_r, 0, SEEK_END);

	size_t flSize=ftell(fl_r);

	if (flSize<10*SZ_MALLOC) return ERR_LESS_THAN_SZ_MALLOC;

	if (fseek(fl_r, (flSize-SZ_MALLOC), SEEK_SET)) return ERR_SEEK_FILE_POSITION;

	if (fread(buf_a,1,SZ_MALLOC,fl_r)^SZ_MALLOC) return ERR_READING_FILE;

	memcpy(nm, buf_a, sizeof(struct magic_number_t));

	memcpy(est, buf_a+sizeof(struct magic_number_t), sizeof(struct structure_t));

	return SUCCESS;
}

int extract_stg_file(char *filename, struct magic_number_t *nm, struct structure_t *est, char chk_sum[SHA256_DIGEST_LENGTH])
{

#ifdef DEBUG
	char tmp[1024];
#endif

	char passwd_tmp_a[MAX_PASS_LENGTH];

	int err=SUCCESS;

	unsigned char *buf = malloc(BUF_FILE_SZ);

	if (!buf) return ENOMEM;

	unsigned char *bufWrite=malloc(BUF_FILE_SZ);

	if (!bufWrite) return ENOMEM;

	FILE *fl_r=fopen(filename,"rb");
	FILE *fl_w;

	size_t sizeOfHiddenFile;
	size_t bytesToRead;
	size_t bytesWritten;

	size_t bytesRead;
	size_t origFileSZ;

	SHA256_CTX fsha256;

	unsigned char privkeyA[AES_BLK_SZ];
	unsigned char privkeyB[AES_BLK_SZ];
	unsigned char iv[AES_BLK_SZ];
	unsigned char salt[AES_BLK_SZ];

	AES_KEY decKey;

	int i;

	size_t overhead;

	if (fl_r)
	{
		if (!(err=get_stg_info(fl_r,nm,est,buf)))
		{

			if (memcmp(&magic_number,nm,sizeof(magic_number)-2*sizeof(int)))
				err=ERR_INVALID_MAGIC_NUMBER;
			else	if (fl_w=fopen(est->filename,"rb"))
			{
				fclose(fl_w);
				err = ERR_FILE_ALREADY_EXISTS; // Arquivo existe
			}
			else
			{
				if (fl_w=fopen(est->filename,"wb")) // cria arquivo pra
				{

					origFileSZ=(size_t)est->skip;

					if (est->hidden_type==HIDDEN_TYPE_AES256_SALT)
					{
						if (fseek(fl_r,0,SEEK_SET))
						{
							fclose(fl_r);
							fclose(fl_w);
							err=ERR_SEEK_FILE_POSITION;
							goto extrair_arquivo_SAIR_ENC;
						}

						SHA256_Init(&fsha256);

						if (BUF_FILE_SZ>=origFileSZ)
						{
							if (fread(bufWrite,1,origFileSZ,fl_r)^origFileSZ)
							{
								fclose(fl_r);
								fclose(fl_w);
								err=ERR_READING_FILE;
								goto extrair_arquivo_SAIR_ENC;
							}
							SHA256_Update(&fsha256, buf, bytesToRead);
						}
						else
						{
							bytesToRead=BUF_FILE_SZ;
							bytesRead=0;
							do
							{
								if (fread(buf, 1, bytesToRead, fl_r)^bytesToRead)
								{
									fclose(fl_r);
									fclose(fl_w);
									err=ERR_READING_FILE;
									goto extrair_arquivo_SAIR_ENC;
								}
								bytesRead+=bytesToRead;

								SHA256_Update(&fsha256, buf, bytesToRead);

								if ((bytesRead+bytesToRead)>origFileSZ)
									bytesToRead=(origFileSZ-bytesRead);
							
							} while (origFileSZ>bytesRead);
						}

						SHA256_Final(DEST_FILE_SHA256SUM, &fsha256);

						if (fread(buf,1,2*AES_BLK_SZ,fl_r)^2*AES_BLK_SZ)
						{
							// Encrypted SALT with privkeyA and Encrypted SHA256 HASH orig file with privkeyB
							fclose(fl_r);
							fclose(fl_w);
							err=ERR_READING_FILE;
							goto extrair_arquivo_SAIR_ENC;
						}

#ifdef DEBUG
						fhex2str(DEST_FILE_SHA256SUM,AES_BLK_SZ,tmp);
						printf("\nMain file SHA256 %s\n",tmp); //SHA256 do arquivo principal
						fhex2str(buf, 2*AES_BLK_SZ, tmp);
						printf("\nSize of first 64 Bytes: %s\n",tmp); //Tamanho dos primeiros 64 bytes
#endif

						SHA256_Init(&fsha256);


						memset(passwd_tmp_a, 0, sizeof(passwd_tmp_a));

						printf(MSG_TYPE_YOUR_PASSWORD_FOR_DECRYPT);
						if (!(err=get_passwd(passwd_tmp_a))) goto PASS_OK;

//PASS_FAIL:
						memset(passwd_tmp_a, 0, sizeof(passwd_tmp_a));
						fclose(fl_r);
						fclose(fl_w);
						goto extrair_arquivo_SAIR;
PASS_OK:
#ifdef DEBUG
						printf("\nTyped password: \"%s\"\n", passwd_tmp_a); //Password digitada foi
						printf("\nSize of password %d\n", sizeof(passwd_tmp_a)); //Tamanho do passwd_tmp_a
#endif
						printf(MSG_DECRYPTING, est->filename);

						SHA256_Update(&fsha256,passwd_tmp_a,strlen(passwd_tmp_a));
						SHA256_Final(salt,&fsha256);

#ifdef DEBUG
						fhex2str(salt,AES_BLK_SZ, tmp);
						printf("\nPassword SHA256 \"%s\": %s\n", passwd_tmp_a, tmp); //SHA256 do passwd
#endif

						for (i=0;i<AES_BLK_SZ;i++)
							salt[i]^=DEST_FILE_SHA256SUM[i];
#ifdef DEBUG
						fhex2str(salt,AES_BLK_SZ, tmp);
						printf("\nXOR(SALT,HASH_PASSWORD): %s ", tmp); //xor do salt e do hash_passwd:
#endif
						if (get_private_key(passwd_tmp_a,salt,privkeyA))
						{
							fclose(fl_r);
							fclose(fl_w);
							err=ERR_GET_PRIVATE_KEY;
							goto extrair_arquivo_SAIR_ENC;
						}

#ifdef DEBUG
						fhex2str(privkeyA,AES_BLK_SZ, tmp);
						printf("\nprivateKeyA = %s: ", tmp);

#endif

						AES_set_decrypt_key(privkeyA, 8*AES_BLK_SZ, &decKey);
						memcpy(iv, DEST_FILE_SHA256SUM,AES_BLK_SZ);
						AES_cbc_encrypt(buf, salt, AES_BLK_SZ, &decKey, iv, AES_DECRYPT);


#ifdef DEBUG
						fhex2str(salt,AES_BLK_SZ, tmp);
						printf("\nExtracting possible \"salt\" of private key B = %s: ", tmp); //Extraindo o suposto \"salt\" da chave privada B =

#endif

						if (get_private_key(passwd_tmp_a, salt, privkeyB))
						{
							fclose(fl_r);
							fclose(fl_w);
							err=ERR_GET_PRIVATE_KEY;
							goto extrair_arquivo_SAIR_ENC;
						}

#ifdef DEBUG
						fhex2str(privkeyB,AES_BLK_SZ, tmp);
						printf("\nExtracting possible private key B = %s: ", tmp); // Extraindo a suposta chave privada B =
#endif
						memcpy(iv, buf, AES_BLK_SZ);
						AES_set_decrypt_key(privkeyB, 8*AES_BLK_SZ, &decKey);
						AES_cbc_encrypt(buf+AES_BLK_SZ, buf+2*AES_BLK_SZ, AES_BLK_SZ, &decKey, iv, AES_DECRYPT);

#ifdef DEBUG
						fhex2str(buf,3*AES_BLK_SZ, tmp);
						printf("\nDesencrypting second block with private key B and writing result into third block = %s: ", tmp); //Desencriptando o 2do bloco com privkeyB e guandando no terceiro bloco =
						printf("\nSize of AES_BLK_SZ: %d\n", AES_BLK_SZ); //Tamanho do AES_BLK_SZ

#endif

						if (memcmp(DEST_FILE_SHA256SUM, buf+2*AES_BLK_SZ, AES_BLK_SZ))
						{
#ifdef DEBUG
							printf("\nFail when desencrypting\n");//Falha ao descriptografar
#endif
							fclose(fl_r);
							fclose(fl_w);
							err=ERR_SHA256_CHECKSUM_FAILED;
							goto extrair_arquivo_SAIR_ENC;
						}
#ifdef DEBUG
						printf("\nDescencryption SUCCESS\n"); //SUCESSO ao descriptografar
#endif

						memset(privkeyA,0,AES_BLK_SZ);
						memset(salt,0,AES_BLK_SZ);
						memset(passwd_tmp_a,0,sizeof(passwd_tmp_a));

						if ((overhead=(size_t)est->overhead)<(sizeOfHiddenFile=(size_t)est->size))
						{
							fclose(fl_r);
							fclose(fl_w);
							err=ERR_OVERHEAD_FILE;
							goto extrair_arquivo_SAIR_ENC;
						}

						memcpy(iv, buf+AES_BLK_SZ, AES_BLK_SZ);
						SHA256_Init(&fsha256);

						if (overhead<=BUF_FILE_SZ)
						{
							if (fread(buf,1, overhead,fl_r)^overhead) err=ERR_READING_FILE;
							else
							{

								AES_cbc_encrypt(buf, bufWrite, overhead, &decKey, iv, AES_DECRYPT);

								if (fwrite(bufWrite,1,sizeOfHiddenFile,fl_w)^sizeOfHiddenFile)
									err=ERR_WRITING_FILE;
								else
									SHA256_Update(&fsha256, bufWrite, sizeOfHiddenFile);
							}
						}
						else
						{

							bytesWritten=0;
							bytesToRead=BUF_FILE_SZ;
							bytesRead=BUF_FILE_SZ;
							do
							{
								if (fread(buf,1,bytesToRead,fl_r)^bytesToRead)
								{
									err=ERR_READING_FILE;
									break;
								}

								AES_cbc_encrypt(buf, bufWrite, bytesToRead, &decKey, iv, AES_DECRYPT);
								memcpy(iv,buf+bytesToRead-AES_BLK_SZ,AES_BLK_SZ);

								if ((bytesWritten+bytesToRead)>=sizeOfHiddenFile)
									bytesRead = sizeOfHiddenFile-bytesWritten;

								bytesWritten+=bytesToRead;

								if (fwrite(bufWrite,1,bytesRead,fl_w)^bytesRead)
								{
									err=ERR_WRITING_FILE;
									break;
								}

								SHA256_Update(&fsha256, bufWrite, bytesRead);

								if ((bytesWritten+bytesToRead)>overhead)
									bytesToRead=(overhead-bytesWritten);

							} while (bytesWritten<sizeOfHiddenFile);
						}
					}
					else if (est->hidden_type==HIDDEN_TYPE_PLAINTEXT)
					{
						printf(MSG_EXTRACTING_HIDDEN_FILE, est->filename);
						if (fseek(fl_r, origFileSZ, SEEK_SET))
						{
							fclose(fl_r);
							fclose(fl_w);
							err=ERR_SEEK_FILE_POSITION;
							goto extrair_arquivo_SAIR;
						}

						SHA256_Init(&fsha256);

						if ((sizeOfHiddenFile=(size_t)est->size)<=BUF_FILE_SZ)
						{
							if (fread(bufWrite,1,sizeOfHiddenFile,fl_r)^sizeOfHiddenFile) err =19;
							else
							{
								if (fwrite(bufWrite,1,sizeOfHiddenFile,fl_w)^sizeOfHiddenFile)
									err=ERR_WRITING_FILE;
								else
									SHA256_Update(&fsha256, bufWrite, sizeOfHiddenFile);
							}
						}
						else
						{

							bytesWritten=0;
							bytesToRead=BUF_FILE_SZ;
							do
							{

								if (fread(bufWrite,1,bytesToRead,fl_r)^bytesToRead)
								{
									err=ERR_READING_FILE;
									break;
								}

								if (fwrite(bufWrite,1,bytesToRead,fl_w)^bytesToRead)
								{
									err=ERR_WRITING_FILE;
									break;
								}

								SHA256_Update(&fsha256, bufWrite, bytesToRead);

								bytesWritten+=bytesToRead;

								if ((bytesWritten+bytesToRead)>sizeOfHiddenFile)
									bytesToRead=(sizeOfHiddenFile-bytesWritten);

							} while (bytesWritten<sizeOfHiddenFile);
						}
					}
					else
					{
						fclose(fl_r);
						fclose(fl_w);
						err=ERR_UNKNOWN_CYPHER_MODE;
						goto extrair_arquivo_SAIR;
					}

					if (!err)
					{
						printf(MSG_CHECKING_HIDDEN_FILE_INTEGRITY);
						SHA256_Final(chk_sum, &fsha256);
						if (memcmp(est->SHA256SUM, chk_sum, SHA256_DIGEST_LENGTH)) err=ERR_SHA256_CHECKSUM_FAILED;
					}
					fclose(fl_w);
				}
				else
					err=ERR_UNABLE_CREATE_FILE; // Impossivel criar arquivo
			}

		}
		fclose(fl_r);
	}
	else
		err=ERR_UNABLE_OPENING_FILE;

	if (est->hidden_type==HIDDEN_TYPE_PLAINTEXT)
		goto extrair_arquivo_SAIR;

extrair_arquivo_SAIR_ENC:

#ifdef DEBUG
	printf("\nOriginal password: %s\n", passwd_tmp_a); //Password original
	fhex2str(passwd_tmp_a, MAX_PASS_LENGTH, tmp);
	printf("\nPassword = %s\nField size %d\n", tmp, MAX_PASS_LENGTH);
	if (strlen(passwd_tmp_a)==0)
	{
		memset(passwd_tmp_a,'A',MAX_PASS_LENGTH-1);
		passwd_tmp_a[MAX_PASS_LENGTH]=0;
		printf("\nForced password: %s\n With size %d\n", passwd_tmp_a,strlen(passwd_tmp_a));
	}
#endif

	memset(passwd_tmp_a, 0, sizeof(passwd_tmp_a));
	memset(privkeyA,0,AES_BLK_SZ);
	memset(privkeyB,0,AES_BLK_SZ);
	memset(iv,0,AES_BLK_SZ);
	memset(salt,0,AES_BLK_SZ);
	memset(&decKey,0,AES_BLK_SZ);

#ifdef DEBUG
	fhex2str(passwd_tmp_a, MAX_PASS_LENGTH, tmp);
	printf("\nPassword (after) = %s\nField size %d\n", tmp, MAX_PASS_LENGTH);
#endif
extrair_arquivo_SAIR:
	free(buf);
	free(bufWrite);

	return err;
}

int read_structure(char *filename, struct magic_number_t *nm, struct structure_t *est)
{

	int err;
	unsigned char *buf = malloc(SZ_MALLOC); // O valor do offset é gravado nos 8 bytes (obrigatório)

	if(!buf) return ENOMEM;

	FILE *fl_r=fopen(filename,"rb");

	if (fl_r)
	{
		err=get_stg_info(fl_r,nm,est,buf);
		fclose(fl_r);
	}
	else
		err=ERR_UNABLE_OPENING_FILE;

	free(buf);

	return err;

}
