/*
 * fencrypt.h
 * This file is part of fstg
 *
 * Copyright (C) 2018 - Fábio Pereira da Silva
 *
 * fstg is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * fstg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with fstg. If not, see <http://www.gnu.org/licenses/>.
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

