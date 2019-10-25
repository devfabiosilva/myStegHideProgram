/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2018
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

#ifdef DEBUG

void fhex2str (unsigned char *ch, size_t size, char *out)
{

    size_t i = 0;

    for(i = 0; i < size; i++)
    {
        sprintf(out + (i * 2), "%02x", (unsigned char)ch[i]);
    }

    out[2*size] = 0;
}

#endif

int sha256_file(FILE *fl, unsigned char buf[SHA256_DIGEST_LENGTH])
{

	unsigned char *buffer = malloc(BUF_FILE_SZ);

	if (!buffer) return ENOMEM;

	size_t bytesRead;

	SHA256_CTX sha256;
	SHA256_Init(&sha256);

	while((bytesRead = fread(buffer, 1, BUF_FILE_SZ, fl)))
		SHA256_Update(&sha256, buffer, bytesRead);

	SHA256_Final(buf, &sha256);
	free(buffer);
	return SUCCESS;
}

void sha256_hash_string (char hash[SHA256_DIGEST_LENGTH], char outputBuffer[2*SHA256_DIGEST_LENGTH+1])
{
    int i = 0;

    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", (unsigned char)hash[i]);
    }

    outputBuffer[2*SHA256_DIGEST_LENGTH] = 0;
}

int insert_steg_file(FILE *fl, FILE *dst_fl, int toEncrypt, char *passwd,unsigned char buf[SHA256_DIGEST_LENGTH])
{

#ifdef DEBUG
	char tmpbuf[1024];
#endif
	unsigned char *buffer = malloc(BUF_FILE_SZ);

	if(!buffer) return ENOMEM;

	unsigned char *buffer_encrypted = malloc(BUF_FILE_SZ);

	if (!buffer_encrypted) return ENOMEM;

	SHA256_CTX sha256;
	SHA256_Init(&sha256);

	size_t bytesRead;
	size_t bytesWrite;

	int result=0;

	unsigned char iv[AES_BLK_SZ];
	unsigned char priv_key_A[AES_BLK_SZ]; // Primeira chave privada usada para criptografar o SALT
	unsigned char priv_key_B[AES_BLK_SZ]; // Segunda chave privada. Usada com iv para criptografar todo o arquivo escondido
	unsigned char salt_A[AES_BLK_SZ];
	char passwd_tmp[8*AES_BLK_SZ];
	int i;
	size_t j;
	size_t overhead = 0;
	AES_KEY encKey;

	if (toEncrypt)
	{
		memset(passwd_tmp,0,sizeof(passwd_tmp));
		strcpy(passwd_tmp,passwd);
		SHA256_Update(&sha256, passwd_tmp, strlen(passwd_tmp));
		SHA256_Final(salt_A, &sha256);
#ifdef DEBUG
		printf("\nPassword %s\n", passwd_tmp);
		sha256_hash_string(salt_A, tmpbuf);
		printf("\nPassword HASH %s\n", tmpbuf);
		sha256_hash_string(DEST_FILE_SHA256SUM, tmpbuf);
		printf("\nHash of fake file %s\n",tmpbuf);
#endif

		for (i=0;i<AES_BLK_SZ;i++)
			salt_A[i]^=DEST_FILE_SHA256SUM[i];
#ifdef DEBUG
		sha256_hash_string(salt_A, tmpbuf);
		printf("\nPassword salt XOR FILE SHA256 = %s\n", tmpbuf);
#endif

		printf(MSG_GENERATING_PRIV_KEY);
		if (get_private_key(passwd_tmp, salt_A, priv_key_A))
		{
			result=ERR_GET_PRIVATE_KEY;
			goto f_SAIR_CRYPT;
		}

#ifdef DEBUG

		sha256_hash_string(priv_key_A, tmpbuf);
		printf("\nPrivate key A = %s\n", tmpbuf);

#endif

		printf(MSG_SALTING_PRIV_KEY);
		if (generate_private_key(passwd_tmp,salt_A,priv_key_B))
		{
			result=ERR_GENERATING_PRIVATE_KEY;
			goto f_SAIR_CRYPT;
		}
		memset(passwd_tmp,0,sizeof(passwd_tmp));

#ifdef DEBUG
		sha256_hash_string(priv_key_B, tmpbuf);
		printf("\nGenerating private key B = %s\n", tmpbuf);
		sha256_hash_string(salt_A, tmpbuf);
		printf("\nGenerating private key salt B %s\n", tmpbuf);
		printf("\nDestroying password %s\n", passwd);

#endif

		AES_set_encrypt_key(priv_key_A, 8*AES_BLK_SZ, &encKey);

		memcpy(iv, DEST_FILE_SHA256SUM, AES_BLK_SZ);

		AES_cbc_encrypt(salt_A, buffer, AES_BLK_SZ, &encKey, iv, AES_ENCRYPT);

		memset(priv_key_A,0,AES_BLK_SZ);
		memset(salt_A,0,AES_BLK_SZ);

		AES_set_encrypt_key(priv_key_B, 8*AES_BLK_SZ, &encKey);
		memcpy(iv, buffer, AES_BLK_SZ);
		AES_cbc_encrypt(DEST_FILE_SHA256SUM, buffer+AES_BLK_SZ, AES_BLK_SZ, &encKey, iv, AES_ENCRYPT);

#ifdef DEBUG

		printf("\nEncrypting private key B salt %s\n", tmpbuf); //Encriptando o sal da chave privada B 
		sha256_hash_string(buffer, tmpbuf);
		printf("\nEncrypted private key B salt %s\n", tmpbuf);//Sal da chave privada B encriptado

#endif

		if (fwrite(buffer,1,2*AES_BLK_SZ,dst_fl)^2*AES_BLK_SZ)
		{
			result=ERR_WRITING_FILE;
			goto f_SAIR_CRYPT;
		}

		memcpy(iv, buffer+AES_BLK_SZ, AES_BLK_SZ);

#ifdef DEBUG
		sha256_hash_string(priv_key_A, tmpbuf);
		printf("\nDestroying private key A %s\n",tmpbuf); //Destruindo a chave privada A
		sha256_hash_string(salt_A, tmpbuf);
		printf("\nDestroying private key B salt %s\n", tmpbuf); //Destruindo o sal da chave privada B 
		sha256_hash_string(iv, tmpbuf);
		printf("\nStarting iv = %s\n",tmpbuf); //Iniciando o iv
#endif

		SHA256_Init(&sha256);

#ifdef DEBUG

		sha256_hash_string(priv_key_B, tmpbuf);
		printf("\nPreparing to encrypt file with private key B = %s\n", tmpbuf); //Preparando pra encriptar o arquivo com a chave B
#endif
		printf(MSG_ENCRYPTING_HIDDEN_FILE);
		while((bytesRead = fread(buffer, 1, BUF_FILE_SZ, fl)))
	    	{
			SHA256_Update(&sha256, buffer, bytesRead);

			if (bytesRead<AES_BLK_SZ)
			{
				memset(buffer+bytesRead,0,(AES_BLK_SZ-bytesRead));
				bytesRead=AES_BLK_SZ;
			}
			else if (bytesRead<FILE_AES_BLK_SZ) // WARNING ! FILE_AES_BLK_SZ == BUF_FILE_SZ ALWAYS
			{
				for (j=BUF_FILE_SZ>>1;j>bytesRead;j>>=1);
				j+=j;
				memset(buffer+bytesRead,0,(BUF_FILE_SZ-bytesRead));
				bytesRead=j;
			}

			AES_cbc_encrypt(buffer, buffer_encrypted, bytesRead, &encKey, iv, AES_ENCRYPT);
			bytesWrite=fwrite(buffer_encrypted,1, bytesRead, dst_fl);

			if (bytesRead^bytesWrite)
			{
				result=5;
				goto f_SAIR_CRYPT;
			}

			overhead+=bytesWrite;
			memcpy(iv,buffer_encrypted+(bytesRead-AES_BLK_SZ), AES_BLK_SZ);
#ifdef DEBUG
			printf("\nBytes read (enc) %d\n", bytesRead);
			printf("\nBytes write (enc) %d\n",bytesWrite);
#endif

	    	}

		structure.overhead=overhead;
		SHA256_Final(buf, &sha256);
		printf(INTEGRITY_MSG);
#ifdef DEBUG
		sha256_hash_string(buf, tmpbuf);
		printf("\nHidden file HASH %s\n",tmpbuf); //Hash do arquivo escondido
#endif
		goto f_SAIR_CRYPT;

	}
	else
	{
		printf(MSG_HIDDING_FILE);
		while((bytesRead = fread(buffer, 1, BUF_FILE_SZ, fl)))
		{
			SHA256_Update(&sha256, buffer, bytesRead);
			bytesWrite=fwrite(buffer,1, bytesRead, dst_fl);
#ifdef DEBUG
			printf("\nBytes read %d\n", bytesRead);
			printf("\nBytes write %d\n",bytesWrite);
#endif
			if (bytesRead^bytesWrite)
			{
				result=ERR_WRITING_FILE;
				goto f_SAIR;
			}
		}
		printf(INTEGRITY_MSG);
		SHA256_Final(buf, &sha256);
		goto f_SAIR;
	}

f_SAIR_CRYPT:
#ifdef DEBUG

	printf("\nencKey size %d\n", (int)sizeof(encKey)); //Tamanho do encKey
	fhex2str(&encKey,sizeof(encKey),tmpbuf);
	printf("\nencKey value %s\n", tmpbuf); //Valor do encKey

#endif

	memset(passwd_tmp,0,8*AES_BLK_SZ);
	memset(&encKey,0,sizeof(AES_KEY));
	memset(priv_key_A,0,AES_BLK_SZ);
	memset(priv_key_B,0,AES_BLK_SZ);
	memset(iv,0,AES_BLK_SZ);

#ifdef DEBUG
	fhex2str(&encKey,sizeof(encKey),tmpbuf);
	printf("\nencKey value after cleaning: %s\n", tmpbuf); //Valor do encKey depois de limpo:
	sha256_hash_string(priv_key_A, tmpbuf);
	printf("\nPrivate key A (final) %s\n", tmpbuf); //Final chave privada A 
	sha256_hash_string(priv_key_B, tmpbuf);
	printf("\nPrivate key B (final) %s\n", tmpbuf); //Final chave privada B
	sha256_hash_string(iv, tmpbuf);
	printf("\nFinal iv = %s\n", tmpbuf);

#endif

f_SAIR:
	free(buffer_encrypted);
    	free(buffer);
	return result;
}

