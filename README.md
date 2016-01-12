# Encryption_Kernel_Module
Linux kernel module for encrypting/decrypting files

APPROACH:
 - At user space password is encrypted using MD5 algorithm.
 - At kernel space password is encrypted again using MD5 algorithm and 
   stored in the output file.
 - The file is encrypted using AES cipher in CTR mode. Other ciphers 
   and mode are not supported. So -c command line parameter is ignored.
 - Output file is created if it does not exist with user and group ownership of the
   running process and protection same as input file.
 - If zero size file is encrypted or decrypted, zero size output file is created 
   with no encryption or decryption.
 - If input and output file is same encryption is not done.
 - Temporary file is used to protect loss of data of actual output file.
 - If encryption is done successfully, output file is replaced with temporary
   file. If failed temporary file is deleted. Output file is deleted if it was created.
