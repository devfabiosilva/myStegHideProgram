/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2018
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

//Thu Set 05 2018 22:35:50 -03
//Qua 05 Set 2018 22:35:50 -03

int generate_private_key(char *passwd, unsigned char salt[AES_BLK_SZ], unsigned char priv_key[AES_BLK_SZ])
{
	if (RAND_bytes(salt, AES_BLK_SZ)==1)
		return (PKCS5_PBKDF2_HMAC(passwd, strlen(passwd), salt, AES_BLK_SZ, PBKDF2_ITER ,EVP_sha256(),AES_BLK_SZ, priv_key)!=1);
	else
		return 1;
}

int get_private_key(char *passwd, unsigned char salt[AES_BLK_SZ], unsigned char priv_key[AES_BLK_SZ])
{
	return (PKCS5_PBKDF2_HMAC(passwd, strlen(passwd), salt, AES_BLK_SZ, PBKDF2_ITER ,EVP_sha256(),AES_BLK_SZ, priv_key)!=1);
}

