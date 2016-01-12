#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <crypto/md5.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>

#include "xcrypt.h"

asmlinkage extern long (*sysptr)(void *arg);

/*
 * Check if input and output files are same 
 */

static int xcrypt_validate_files(struct file *in_filp, struct file *out_filp)
{
	struct inode *in_inode = file_inode(in_filp);
	struct inode *out_inode = file_inode(out_filp);

	if((in_inode->i_ino == out_inode->i_ino) &&
	   (in_inode->i_sb->s_dev == out_inode->i_sb->s_dev)) 
		return -EPERM ;
	return 0;			
}

/*
 * Encrypts data with AES cipher
 */

static int xcrypt_encrypt_data(unsigned char *key, unsigned int keylen,
			unsigned char *buf, unsigned int buflen,
			unsigned int encrypt)
{
	char iv[128];
	struct crypto_blkcipher *tfm;
	struct blkcipher_desc desc;
	struct scatterlist sg;
	unsigned int iv_len;
	int ret = 0;

	sg_init_one(&sg,(u8 *)buf,buflen);

	tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		goto out;
	}
	desc.tfm = tfm;
	desc.flags = 0;

	ret = crypto_blkcipher_setkey(tfm, key, keylen);
	if (ret < 0)
		goto error;

	iv_len = crypto_blkcipher_ivsize(tfm);
	if (iv_len) {
		memset(&iv, 0xff, iv_len);
		crypto_blkcipher_set_iv(tfm, iv, iv_len);
	}
	if(encrypt)
		ret = crypto_blkcipher_encrypt(&desc, &sg, &sg, buflen);
	else
		ret = crypto_blkcipher_decrypt(&desc, &sg, &sg, buflen);

error:
	crypto_free_blkcipher(tfm);
out:
	return ret;
}

/*
 * Generate Hash using MD5 algorithm. It is stored in preamble
 */
 
static int xcrypt_generate_hash(unsigned char* key, unsigned int len,
			 unsigned char *hash)
{
	struct scatterlist sg;
	struct crypto_hash *tfm;
	struct hash_desc desc;
	int ret = 0;

	sg_init_one(&sg,(u8 *)key,len);

	tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
	{
		ret = PTR_ERR(tfm);
		goto error;
	}
	desc.tfm = tfm;
	desc.flags = 0;

	ret = crypto_hash_digest(&desc, &sg, len, hash);

	crypto_free_hash(tfm);
error:
	return ret;
}

/*
 * Function to write to file. Not many checks as it is internally
 * done in vfs_write.
 */

static int xcrypt_write_file(struct file *filp, void *buf, int len)
{
	mm_segment_t oldfs;
	int bytes;
	
	if (!S_ISREG(file_inode(filp)->i_mode))
		return -EINVAL;
	if (!filp->f_op->write)
		return -EIO;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	bytes = vfs_write(filp, buf, len, &filp->f_pos);
	set_fs(oldfs);

	return bytes;
}


/*
 * Function to read from file. Not many checks as it is internally
 * done in vfs_read.
 */

static int xcrypt_read_file(struct file *filp, void *buf, int len)
{
	mm_segment_t oldfs;
	int bytes;
	int size;
	
	if (!S_ISREG(file_inode(filp)->i_mode))
		return -EINVAL;
	size = i_size_read(file_inode(filp));
	if (size <= 0)
		return -EINVAL;
	if (!filp->f_op->read)
		return -EIO;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	bytes = vfs_read(filp, buf, len, &filp->f_pos);
	set_fs(oldfs);

	return bytes;
}


/*
 * Unlinks file in case of error.
 * No error checking done so actual error can be
 * returned to the user.
 */

static void xcrypt_unlink_file(struct file *filp)
{
	struct dentry *dentry = filp->f_path.dentry;
	struct dentry *p_dentry = dget_parent(dentry);

	mutex_lock(&p_dentry->d_inode->i_mutex);
	vfs_unlink(p_dentry->d_inode, dentry , NULL);
	mutex_unlock(&p_dentry->d_inode->i_mutex);
}



static int xcrypt_rename_file(struct file *oldfilp, struct file *newfilp)
{
	int ret = 0;

	struct dentry *dentry = oldfilp->f_path.dentry;
	struct dentry *old_dentry = dget_parent(dentry);
	struct dentry *new_dentry = dget_parent(newfilp->f_path.dentry);
   
	lock_rename(old_dentry, new_dentry);
	ret = vfs_rename(old_dentry->d_inode, dentry, new_dentry->d_inode,
		 newfilp->f_path.dentry, NULL, 0);
	unlock_rename(old_dentry, new_dentry);
	
	return ret;
}		

/*
 * Creates new file with user and group id as of base file
 * and returns handle to new file as out parameter newfilp.
 * Permission will be later changed to match input file permissions.
 */
static int xcrypt_create_tmp_file(struct file *basefilp, struct file **newfilp)
{
	struct inode *n_inode;
	struct inode *b_inode = file_inode(basefilp);
	const char *tmpfile = ".xcrypt.tmp";

	*newfilp  = filp_open(tmpfile,O_RDWR | O_CREAT, b_inode->i_mode);
	if (!(*newfilp)) {
		return -EINVAL;
	}
	if (IS_ERR(*newfilp)) {
		return  PTR_ERR(*newfilp);
	}
	n_inode = file_inode(*newfilp);
	n_inode->i_uid = b_inode->i_uid;
	n_inode->i_gid = b_inode->i_gid;

	(*newfilp)->f_pos = 0;

	return 0;
}

/*
 * Compare the hash with the key in preamble and 
 * decrypt file i_filp and writes to t_filp if matches.
 */

static int xcrypt_decrypt_file(struct file *i_filp, struct file *t_filp,
			       unsigned char *hash, int len)
{
	int ret = 0;
	int bytes_read = 0;
	int bytes_write = 0;
	int size = 0;
	char buf_read[PAGE_SIZE+1];	
	unsigned char preamble[MD5_DIGEST_SIZE];

	size = i_size_read(file_inode(i_filp));
	if (size==0)
		goto err;
	size = size - len;
	if (size <= 0) {
		ret = -EINVAL;
		goto err;
	}
	bytes_read = xcrypt_read_file(i_filp, &preamble,MD5_DIGEST_SIZE);
	if (bytes_read < 0) {
		ret = bytes_read;
		goto err;
	}
	if (memcmp((unsigned char*)preamble,hash,len)) {
		ret = -EACCES;
		goto err;
	}

	while(size>0)
	{
		bytes_read = xcrypt_read_file(i_filp,buf_read,PAGE_SIZE);
		if (bytes_read < 0) {
			ret = bytes_read;
			goto err;
		}
		ret = xcrypt_encrypt_data(hash,MD5_DIGEST_SIZE,buf_read,
					  bytes_read,0);
		if (ret<0)
			goto err;
		bytes_write = xcrypt_write_file(t_filp,buf_read,bytes_read);
		if(bytes_write < 0) {
			ret = bytes_write;
			goto err;
		}
		size = size - bytes_read;
	}
err:
	return ret;
}

/*
 * Store the hash in preamble and encrypt file using the hash.
 */

static int xcrypt_encrypt_file(struct file *i_filp, struct file *t_filp,
			       unsigned char *hash)
{
	int bytes_write = 0;
	int bytes_read = 0;
	int size = 0;
	int ret = 0;
	char buf_read[PAGE_SIZE+1];	

	size = i_size_read(file_inode(i_filp));
	if (size<=0)
		goto err;

	bytes_write = xcrypt_write_file(t_filp,hash,MD5_DIGEST_SIZE);
	if (bytes_write < 0) {
		ret = bytes_write;
		goto err;
	}
	while(size>0)
	{
		bytes_read = xcrypt_read_file(i_filp,buf_read,PAGE_SIZE);
		if (bytes_read < 0) {
			ret = bytes_read;
			goto err;
		}
		ret = xcrypt_encrypt_data(hash,MD5_DIGEST_SIZE,buf_read,
					  bytes_read,1);
		if (ret<0)
			goto err;
		bytes_write = xcrypt_write_file(t_filp,buf_read,bytes_read);
		if(bytes_write < 0) {
			ret = bytes_write;
			goto err;
		}
		size = size - bytes_read;
	}
err:
	return ret;
}

/*
 * It validates the input and output files and finally encrypts
 * or decrypts the file.
 */

int validate_encrypt_file(const char *infile, const char *outfile, 
	unsigned char *key, unsigned int len, unsigned int encrypt)
{
	int ret = 0;
	int out_creat = 0;
	unsigned char hash[MD5_DIGEST_SIZE];
	struct file *i_filp, *o_filp;
	struct file *t_filp = NULL;
	
 
	i_filp = filp_open(infile, O_RDONLY, 0);
	if (!i_filp || IS_ERR(i_filp)) {
		ret =  PTR_ERR(i_filp);
		goto out;
	}

	o_filp = filp_open(outfile, O_RDWR, 0);
	if (!o_filp || IS_ERR(o_filp)) {
		out_creat = 1;
	} else {
		ret = xcrypt_validate_files(i_filp,o_filp);    
		if (ret < 0)
			goto err_ofile;
	}
	if (out_creat) {
		o_filp = filp_open(outfile, O_RDWR | O_CREAT, file_inode(i_filp)->i_mode);
		if (!o_filp) {
			out_creat = 0; 
			ret = -EINVAL;
			goto err_ifile;
		}
		if (IS_ERR(o_filp)) {
			out_creat = 0;
			ret = PTR_ERR(o_filp);
			goto err_ifile;
		}
	}

	ret = xcrypt_create_tmp_file(o_filp, &t_filp);
	if (ret < 0)
		goto err_ofile;

	i_filp->f_pos = 0;
	o_filp->f_pos = 0;

	ret = xcrypt_generate_hash(key, len, hash);
	if (ret < 0)
		goto err;
		
        if (encrypt){
		ret = xcrypt_encrypt_file(i_filp, t_filp, hash);
		if (ret < 0)
			goto err;
	} else {
		ret = xcrypt_decrypt_file(i_filp, t_filp, hash, len);
		if (ret < 0)
			goto err;
	}
err:
	if (ret >= 0) 
		ret = xcrypt_rename_file(t_filp, o_filp);
	else 
		xcrypt_unlink_file(t_filp);
	filp_close(t_filp, NULL);
err_ofile:
/* If there is error and outfile is created unlink it */
	if ( ret < 0 && out_creat){
		xcrypt_unlink_file(o_filp);	
	}
	filp_close(o_filp, NULL);
err_ifile:
	filp_close(i_filp, NULL);
out:
	return ret;
}

asmlinkage long xcrypt(void *arg)
{

	struct xcrypt_args* kargs = NULL;
	struct filename *infile = NULL;
	struct filename *outfile = NULL;

	int ret = -EINVAL;
	if (!arg) 
		goto out;
	
	kargs = (struct xcrypt_args*) kmalloc(sizeof(struct xcrypt_args),
					      GFP_KERNEL);
	if (unlikely(!kargs)) {
		ret = -ENOMEM;
		goto out;
	}
        if (copy_from_user(kargs, arg, sizeof(struct xcrypt_args))) {
		ret = -EFAULT;
		goto outcopy;
	}
	if (!(kargs->infile) || !(kargs->outfile))
		goto outcopy;

	infile =  getname(kargs->infile);
	if (IS_ERR(infile)) {
		ret = PTR_ERR(infile);
		goto outcopy;
	}
         
	outfile =  getname(kargs->outfile);
	if (IS_ERR(outfile)) {
		ret= PTR_ERR(outfile);
		goto err_ofile;
	}

	if (((struct xcrypt_args*)arg)->keybuf) {
		kargs->keybuf = (char *)kmalloc (kargs->keylen, GFP_KERNEL);
		if (unlikely(!kargs)) {
			ret = -ENOMEM;
			goto err_keybuf;
		}

		if (copy_from_user(kargs->keybuf,
			((struct xcrypt_args*)arg)->keybuf,kargs->keylen)) {
			ret = -EFAULT;
			goto err_key;
		}
	}
	
	ret = validate_encrypt_file(infile->name,outfile->name,
			 kargs->keybuf, kargs->keylen, kargs->flags);
err_key:
	kfree(kargs->keybuf);
err_keybuf:
	putname(outfile);
err_ofile:
	putname(infile);
outcopy:
	kfree(kargs);
out:
	return ret;
	
}

static int __init init_sys_xcrypt(void)
{
	printk("installed new sys_xcrypt module\n");
	if (sysptr == NULL)
		sysptr = xcrypt;
	return 0;
}
static void  __exit exit_sys_xcrypt(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xcrypt module\n");
}
module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);
MODULE_LICENSE("GPL");

