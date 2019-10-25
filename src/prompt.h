/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2018
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

// Sáb 15 Set 2018 20:49:29 -03

int get_passwd(char pass[MAX_PASS_LENGTH])
{
	struct termios oflags, nflags;
	int err;
	int i;
	char pass_tmp[MAX_PASS_LENGTH];
	memset(pass_tmp,0,MAX_PASS_LENGTH);

	tcgetattr(fileno(stdin), &oflags);
	nflags = oflags;
	nflags.c_lflag &= ~ECHO;
	nflags.c_lflag |= ECHONL;

	if (tcsetattr(fileno(stdin), TCSADRAIN, &nflags) != 0) return 10;

	if (!fgets(pass_tmp, (MAX_PASS_LENGTH), stdin))
	{
		err=ERR_UNABLE_TO_READ_STDIN;
		goto PASS_ERR;
	}

	err=ERR_MAX_PASS_LENGTH;
	
	for (i=0;i<MAX_PASS_LENGTH;i++)
		if ((pass[i]=pass_tmp[i])==0x0A)
		{
			if (i)
			{
				pass[i]=0;
				err=SUCCESS;
			}
			else
				err=ERR_PASS_NULL;
			break;
		}

PASS_ERR:

	memset(pass_tmp,0,MAX_PASS_LENGTH);

	if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) return (ERR_UNABLE_TO_RESTORE_CONSOLE|err);

	return err;
}

