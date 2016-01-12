
#ifndef XCRYPT_H_
#define XCRYPT_H__


struct xcrypt_args {
	char* infile;
	char* outfile;
	unsigned char* keybuf;
	unsigned int keylen;
	unsigned int flags;
};


#endif /* XCRYPT_H_  */
