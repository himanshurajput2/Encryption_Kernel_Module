#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <asm/unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <limits.h>
#include <openssl/ssl.h>
#include <openssl/md5.h>

#include "xcrypt.h"

#ifndef __NR_xcrypt
#error xcrypt system call not defined
#endif

#define KEYLEN 16

static const char* exec_name;

static void argerr (const char *format, ...)
{
	va_list ap;
	va_start (ap, format);
	fprintf (stderr, "%s: ", exec_name);
	vfprintf (stderr, format, ap);
	fprintf (stderr, "Try '%s -h' for more information.\n", exec_name);
	va_end (ap);
	exit (1);
}

static void usage()
{
	printf("Usage:\n");
	printf("-p ""this is my password"" -e infile outfile\n");
	printf("Pass three arguments:\n");
	printf("-d to decrypt\n");
	printf("-e to encrypt\n");
	printf("-c ARG to specify the type of xcipher (as a string name)  \n");
	printf("-p ARG to specify the encryption/decryption key  \n");
	printf("-input file name  \n");
	printf("-output file name \n");
}

void generate_key(const char* key, int keylen, unsigned char* keybuf)
{
	MD5_CTX context;
	
	MD5_Init(&context);

	MD5_Update(&context, key, keylen);
	MD5_Final(keybuf, &context);
}

int main(int argc, char* argv[])
{
	int encrypt = -1;
	const char* cipher_type = NULL;
	const char* encrypt_key = NULL;
	const char* infile = NULL;
	const char* outfile = NULL;
	extern char *optarg;
	extern int optind;
	int  ch;
	int rc;
	char buf[PATH_MAX + 1] = {0};
	
	exec_name = argv[0];

	if (argc == 1 || (argc == 2 && strcmp("-h", argv[1]))) {
		argerr("Wrong Usage\n");
	}	
	if (argc == 2 && !strcmp("-h", argv[1])) {
		usage();
		return 0;
	}
	 
	while ((ch = getopt(argc, argv, "edc:p:")) != -1) {
		switch(ch) {
		case 'e': 
			if (encrypt == 0)
				 argerr("Cannot encrypt and decrypt at same time\n");
			encrypt = 1;
			break;
		
		case 'd':
			if (encrypt == 1)
				 argerr("Cannot encrypt and decrypt at same time\n");
			encrypt = 0;
			break;
		case 'c':
			cipher_type = optarg;
			break;
		case 'p':
			encrypt_key = optarg;		
			break;
		case '?':
			argerr("Invalid argument\n");
        	}
	}

	if (encrypt == -1)
		argerr ("Give option to encrypt or decrypt file\n");
	if (!encrypt_key)
		argerr ("Give Password\n");
		
	argc -= optind;
	argv += optind;
	
	if (argc < 2)
		argerr ("Give both input and output file\n");
	if (argc > 2)
		argerr ("Check number of parameters\n");

	infile = *argv;
	if (!infile)
		argerr ("Specify Input file\n");
	argv++;

	outfile = *argv;
	if (!outfile)
		argerr ("Specify Output file\n");
	
	if ((strlen(outfile) < 1) || (strlen(outfile) > PATH_MAX))
		argerr ("Check output file path\n");

	if (strlen(encrypt_key)<6)
		argerr ("Password should be atleast 6 characters long \n");

	struct xcrypt_args* args = 
		(struct xcrypt_args*)malloc(sizeof(struct xcrypt_args));
	if (!args) {
		printf ("Memory Allocation failed\n");
		rc = 1;
		goto out;
	}

	char *res = realpath(infile, buf);
	if (!res) {
		perror("xcrypt");
		rc = 1;
		goto outargs;
	}
	int infile_len = strlen(buf);
	args->infile = (char*)malloc(infile_len+1);

	if (!args->infile) {
		printf ("Memory Allocation failed\n");
			rc = 1;
			goto outargs;
	}
	memcpy(args->infile, buf, infile_len+1);

	args->outfile = (char*)outfile;

	args->keybuf = (unsigned char*)malloc(KEYLEN);
	if (!args->keybuf) {
		printf ("Memory Allocation failed\n");
			rc = 1;
			goto outinfile;
	}

	generate_key(encrypt_key, strlen(encrypt_key), args->keybuf);
	
	args->keylen = KEYLEN;
	args->flags  = encrypt;

	void *dummy = (void *) args;
        
	rc = syscall(__NR_xcrypt, dummy);
	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else {
		printf("syscall returned %d (errno=%d)\n", rc, errno);
		perror("xcrypt");
	}

	free(args->keybuf);
outinfile:
	free(args->infile);
outargs:
	free(args);
out:	
        exit(rc);
}

