/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2018
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

// Standard messages goes here
// Main file
//#define DEF_MSG "\nUsage: \n\n\tfstg add archive_name archive_to_be_hidden\n\n\tOr\n\n\tfstg extract archive_name\n\nOr\n\n\tfstg version to see file version\n\nOr\n\tfstg info archive\nfor file info\n\n"

#define DEF_MSG_ADD "add <DEST. FILE> <FILE TO BE HIDDEN>"
#define DEF_MSG_ADD_DESC "Add the <FILE TO BE HIDDEN> to <DEST. FILE>\n\n"
#define DEF_MSG_ADD_WITH_PASSWORD "add-with-password <DEST. FILE> <FILE TO BE HIDDEN>"
#define DEF_MSG_ADD_WITH_PASSWORD_DESC "Encrypt and add the <FILE TO BE HIDDEN> to <DEST. FILE>\n\n"
#define DEF_MSG_EXTRACT "extract <DEST. FILE>"
#define DEF_MSG_EXTRACT_DESC "Extract an stegged file (if exists) from <DEST. FILE>\n\n"
#define DEF_MSG_INFO "info <DEST. FILE>"
#define DEF_MSG_INFO_DESC "Show stegged file info (if exists) from <DEST. FILE>\n\n"
#define DEF_MSG_USAGE "usage"
#define DEF_MSG_USAGE_DESC "Show program version and details.\n\n"
#define DEF_MSG_VERSION "version"
#define DEF_MSG_VERSION_DESC "Show program version and details.\n\n"

#define DEF_MSG\
"\nUsage:\n\nfstg [OPTIONS] <DEST. FILE> <FILE TO BE HIDDEN>\n\n\n" \
"   " DEF_MSG_ADD "                  " DEF_MSG_ADD_DESC \
"   " DEF_MSG_ADD_WITH_PASSWORD "    " DEF_MSG_ADD_WITH_PASSWORD_DESC \
"   " DEF_MSG_EXTRACT "                                  " DEF_MSG_EXTRACT_DESC \
"   " DEF_MSG_INFO "                                     " DEF_MSG_INFO_DESC \
"   " DEF_MSG_USAGE "                                                 " DEF_MSG_USAGE_DESC \
"   " DEF_MSG_VERSION "                                               " DEF_MSG_VERSION_DESC
#define DEF_MSG_02 "\nError: %d\nDestination and Hidden file are the same\n"
#define STG_FILE_NAME_MAX "\nMax file name \"%s\" size is greater than %lu.\n"
#define STG_FILE_NAME_NULL "\nEmpty file name.\n"
#define INTEGRITY_MSG "\nChecking integrity record ...\n"
#define MSG_MAX_STR_LEN "\nError\nExiting...\nSome pointer declared string is not a string and/or string exceeds MAX_STR_LEN = %d\n"
#define MSG_MISSING_FILE "ERROR:\nMissing: file to add a hidden archive\n"
#define MSG_MANY_ARG "\nToo much arguments: %s\n"
#define MSG_FEW_ARG "\nFew arguments\n"
#define MSG_FILE_NOT_FOUND "Error:\nFile \"%s\" not found.\n\n"
#define MSG_HIDDEN_FILE_NOT_EXISTS "\nFile to be hidden \"%s\" not exists.\n"
#define MSG_UNABLE_TO_OPEN_DEST_FILE "\nUnable to open destination file \"%s\"to append hidden file \"%s\"."
#define MSG_WARNING_ADDING_HIDDEN_FILE "\nAdding \"%s\" into destination file \"%s\" ...\nWARNING: Everyone may have access to your hidden file.\n"
#define MSG_ERR_IN_FUNCTION "\nError in function \"insert_steg_file\" with Err = %d.\n"
#define MSG_ERR_NO "\nError: %d\n"
#define MSG_FILE_ADDED_SUCCESSFULLY "\nFile \"%s\" added to \"%s\" successfully into %s\n"
#define MSG_FILE_TO_BE_ENCRYPTED_NOT_EXISTS "\nFile to be hidden/encrypted \"%s\" not exists.\n"
#define MSG_UNABLE_TO_OPEN_DEST_FILE_ENCRYPTED "\nUnable to open destination file \"%s\"to append hidden/encrypted file \"%s\"."
#define MSG_TYPE_YOUR_PASSWORD "\nPlease, type your password to encrypt hidden file:\n"
#define MSG_SOMETHING_WENT_WRONG "\nSomething went wrong: %d\n"
#define MSG_RETYPE_YOUR_PASSWORD "\nNow, re-type your password to confirm hidden file encryption:\n"

#define MSG_ERR_WHEN_MACTHING_PASS "\nSomething went wrong when matching password. %d\n"
#define MSG_PASS_DOES_NOT_MATCH "\nPassword does not match. Try again.\n"
#define MSG_ADDING_AND_ENCRYPTING "\nAdding and encrypting \"%s\" into destination file \"%s\" ..."
#define MSG_ERR_INSERT_ENCRYPTED_FILE "\nError when inserting encrypted file \"%s\". Something went wrong %d\n"
#define MSG_MANY_ARG_EXTRACT_FILE "\nMany arguments to extract a file. What is '%s'?\n\n"
#define MSG_FEW_ARG_EXTRACT_FILE "\nFew arguments to extract a file. Type \"fstg usage\" for help.\n"
#define MSG_ERR_WHEN_EXTRACTING_FILE "\nError when extracting file %d\n"
#define MSG_FILE_SUCCESSFUL_EXTRACTED "\nFile \"%s\" successful extracted with HASH256: %s\n"
#define MSG_MANY_ARG_INFO "\nToo many arguments in \"info\". What is '%s'?\n\n"
#define MSG_FEW_ARG_INFO "\nFew arguments for \"info\". Type filename.\n\n"
#define MSG_ERR_WHEN_READING_STRUCTURE "\nERROR %d when reading structure of file \"%s\"\n"
#define MSG_MAGIC_NUMBER_ERROR "\nMagic number error: %d or no hidden file in \"%s\".\n"
#define MSG_INFO_FILE_NAME "\nINFO\nFile name: %s\n"
#define MSG_FILE_SZ_IN_BYTES "File size (in Bytes) %lu\n"
#define MSG_INSERTED_FILE_DATE "Inserted hidden file date: %s\n"
#define MSG_ERR_FILE_UNKNOWN_OR_CORRUPTED "Unknown or corrupted file"
#define YES "YES"
#define NO "NO"
#define MSG_INFO_FILE_ENCRYPTED "\nFile encrypted: %s\n"
#define MSG_INFO_HASH256_FILE "SHA256 hidden file: %s\n"

// version 1.2
#define MSG_DEST_FILE_TOO_SMALL "\nDestination file is smaller than %lu Bytes.\n"
//

//#define MSG_VERSION "\nVersion: %d.%d\n\nFábio Pereira 2018\n\n"
#define MSG_VERSION "\nfstg %d.%d by Fábio Pereira da Silva 2018\n"
#define MSG_UNKNOWN_FILE_CMD "\n\nUnknown file command \"%s\". Type \"fstg usage\" for details.\n\n"
#define MSG_ERR_FINAL "\nFail with error number: %d\n"
#define MSG_SUCCESS_FINAL "\nExit SUCCESS\n"

// for fsha256.h
#define MSG_GENERATING_PRIV_KEY "\nGenerating private key ...\n"
#define MSG_SALTING_PRIV_KEY "\nSalting generated private key ...\n"
#define MSG_ENCRYPTING_HIDDEN_FILE "\nEncrypting and hidding file ...\n"
#define MSG_HIDDING_FILE "\nHidding file ...\n"
#define MSG_TYPE_YOUR_PASSWORD_FOR_DECRYPT "\nType your password to decrypt file:\n"
#define MSG_DECRYPTING "\nDecrypting and extracting hidden file \"%s\" ...\n"
#define MSG_EXTRACTING_HIDDEN_FILE "\nExtracting hidden file \"%s\" ...\n"
#define MSG_CHECKING_HIDDEN_FILE_INTEGRITY "\nChecking hidden file integrity...\n"
/*
#define LICENSE \
MSG_VERSION \
"\n\nCopyright (C) 2016 Free Software Foundation, Inc.\n\
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n\
This is free software: you are free to change and redistribute it.\n\
There is NO WARRANTY, to the extent permitted by law.\n\nAUTHOR: " C_AUTHOR "\n"\
"EMAIL: " C_AUTHOR_EMAIL "\n"
*/
#define LICENSE \
MSG_VERSION \
"\n\nMIT License\n\n"\
"Copyright (c) 2018 "C_AUTHOR"\n\n"\
"Permission is hereby granted, free of charge, to any person obtaining a copy\n"\
"of this software and associated documentation files (the \"Software\"), to deal\n"\
"in the Software without restriction, including without limitation the rights\n"\
"to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n"\
"copies of the Software, and to permit persons to whom the Software is\n"\
"furnished to do so, subject to the following conditions:\n\n"\
"The above copyright notice and this permission notice shall be included in all\n"\
"copies or substantial portions of the Software.\n\n"\
"THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n"\
"IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n"\
"FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n"\
"AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n"\
"LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n"\
"OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n"\
"SOFTWARE.\n\n"
