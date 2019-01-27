/*
 * ffileutil.h
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

int file_not_exists(char *path)
{
	FILE *temp=fopen(path, "rb");

	if (temp)
	{
		fclose(temp);
		return 0;
	}

	return 1;
}

char *is_filename(char *path)
{
	char *ret=strrchr(path, FS);

	if (ret)
		return ret+1;

	return path;
}

char *trunc(char *str)
{
	if (str[0]=='\0') return str;

	size_t len=strlen(str);

	if (len>MAX_STR_LEN)
	{
		printf(MSG_MAX_STR_LEN, MAX_STR_LEN);
		exit(1);
	}

	size_t i;
	size_t k=0;
	size_t m=len-1;

	for (i=m;i>=0; i--)
		if (str[i]==' ')
		{
			str[i]='\0';
			len-=1;
		}
		else
			break;

	for (i=0; i<len;i++)
		if (str[i]!=' ')
			break;
		else
			k++;

	//if (len-=k) strcpy(str, str+k); // removed in 1.1
	if (k) strcpy(str, str+k); // added in 1.1

	return str;
}

