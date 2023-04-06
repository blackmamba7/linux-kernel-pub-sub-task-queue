
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/delay.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/stat.h>
#include <linux/rtc.h>
#include <linux/fs_struct.h>
#include "async_ops.h"

#define OUTPUT_STORE_PATH "/usr/src/hw3-cse506g15/CSE-506/"
#define DOT_OUT_FILE ".out"
#define STR_BUFFER_FOR_JOB_ID 10

struct work_struct_wrapper {
	struct list_head list;
	struct work_struct async_job;
	int operation;
	int job_id;
	int job_status;
	void *args;
	int op_status;
	int status[MAX_NUMBER_OF_FILES];
	int user_id;
	int priority;
	struct timespec time_of_queueing;
};

struct completed_jobs_node {
	struct list_head list;
	int user_id;
	int job_id;
	int op;
	int op_status;
	struct var_args *args;
	int status[MAX_NUMBER_OF_FILES];
};

//Helper function to write to a file
int sys_crypto_write_file(struct file *outfile, void *buf, int len)
{
	int bytes = 0;
	int ret = 0;
	mm_segment_t oldfs;

	if (outfile == NULL) {
		pr_err("Invalid File.\n");
		ret = -EBADFD;
		goto exit;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	bytes = vfs_write(outfile, buf, len, &(outfile->f_pos));
	set_fs(oldfs);

	if (bytes < 0) {
		pr_err("File write error\n");
		ret = -EIO;
		goto exit;
	}

	return bytes;

exit:
	return ret;
}

//Helper cleaner function for compression struct
static void comp_dec_op_cleanup(struct compress_args *args)
{
	kfree(args->input_file_path);
	kfree(args->output_file_path);
	kfree(args);
}

unsigned int get_file_mode(struct file *fl)
{
	return (fl->f_inode->i_mode & 0b111111111);
}

static void compcopy(struct work_struct *job)
{
	int retval = 0;
	struct crypto_comp *crypto_comp = NULL;
	struct file *infile = NULL, *outfile = NULL;
	char *inbuf = NULL, *outbuf = NULL;
	unsigned long long input_file_pos, output_file_pos;
	int no_bytes_read, no_bytes_written;
	int comp_buf_size;
	struct work_struct_wrapper *job_wrapper =
		container_of(job, struct work_struct_wrapper, async_job);
	struct compress_args *args = (struct compress_args *)job_wrapper->args;

	msleep(10000);

	if (args->flag != 1 && args->flag != 2) {
		retval = -EINVAL;
		goto out;
	}

	inbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (inbuf == NULL) {
		printk("Could not allocate memory to input buffer\n");
		retval = -ENOMEM;
		goto out;
	}

	outbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (outbuf == NULL) {
		printk("Could not allocate memory to output buffer\n");
		retval = -ENOMEM;
		goto out;
	}

	crypto_comp = crypto_alloc_comp("lz4", 0, 0);
	if (IS_ERR(crypto_comp)) {
		retval = PTR_ERR(crypto_comp);
		crypto_comp = NULL;
		printk("Failed to initialize crypto compression\n");
		goto out;
	}

	infile = filp_open(args->input_file_path, O_RDONLY, 0);

	if (IS_ERR(infile)) {
		retval = PTR_ERR(infile);
		infile = NULL;
		printk("Failed to open the input file\n");
		goto out;
	}

	outfile = filp_open(args->output_file_path,
			    O_WRONLY | O_CREAT | O_TRUNC, 0777);

	if (IS_ERR(outfile)) {
		retval = PTR_ERR(outfile);
		outfile = NULL;
		printk("Failed to open the output file\n");
		goto out;
	}

	input_file_pos = 0;
	output_file_pos = 0;

	do {
		no_bytes_read =
			kernel_read(infile, inbuf, PAGE_SIZE, &input_file_pos);

		if (no_bytes_read < 0) {
			retval = no_bytes_read;
			printk("Could not read from the file\n");
			goto out;
		}

		if (no_bytes_read == 0)
			break;

		comp_buf_size = PAGE_SIZE;

		if (args->flag & 1) {
			retval = crypto_comp_compress(crypto_comp, inbuf,
						      no_bytes_read, outbuf,
						      &comp_buf_size);
		} else if (args->flag & 2) {
			retval = crypto_comp_decompress(crypto_comp, inbuf,
							no_bytes_read, outbuf,
							&comp_buf_size);
		}

		if (retval) {
			printk("Could not perform compression/decompression\n");
			goto out;
		}

		no_bytes_written = kernel_write(outfile, outbuf, comp_buf_size,
						&output_file_pos);

		if (no_bytes_written < 0) {
			retval = no_bytes_written;
			printk("Could not write to the file\n");
			goto out;
		}
	} while (no_bytes_read > 0);

out:
	if (outfile != NULL)
		filp_close(outfile, NULL);

	if (infile != NULL)
		filp_close(infile, NULL);

	if (crypto_comp != NULL)
		crypto_free_comp(crypto_comp);

	if (inbuf != NULL)
		kfree(inbuf);

	if (outbuf != NULL)
		kfree(outbuf);

	job_wrapper->op_status = retval;
	comp_dec_op_cleanup(args);
	job_wrapper->job_status = COMPLETED;
	return;
}

static void hash_op_cleanup(struct hash_args *args)
{
	kfree(args->input_file_path);
	kfree(args->output_file_path);
	kfree(args);
}

// Function md5_to_hex is copied verbatim from /fs/nfsd/nfs4recover.c in Linux source code
void md5_to_hex(char *out, char *md5)
{
	int i;

	for (i = 0; i < 16; i++) {
		unsigned char c = md5[i];

		*out++ =
			'0' + ((c & 0xf0) >> 4) + (c >= 0xa0) * ('a' - '9' - 1);
		*out++ = '0' + (c & 0x0f) +
			 ((c & 0x0f) >= 0x0a) * ('a' - '9' - 1);
	}
	*out = '\0';
}

void compute_file_hash(struct work_struct *job)
{
	int retval = 0, no_bytes_read, no_bytes_written;
	struct crypto_shash *hash_alg = NULL;
	struct shash_desc *desc = NULL;
	unsigned int desc_size;
	struct file *infile = NULL, *outfile = NULL;
	char *buf = NULL;
	long long int input_file_pos = 0, output_file_pos = 0;
	char file_hash[DIGEST_SIZE + 1], hex_file_hash[2 * DIGEST_SIZE + 1];

	struct work_struct_wrapper *job_wrapper =
		container_of(job, struct work_struct_wrapper, async_job);
	struct hash_args *args = (struct hash_args *)job_wrapper->args;

	msleep(10000);

	infile = filp_open(args->input_file_path, O_RDONLY, 0);
	if (IS_ERR(infile)) {
		retval = PTR_ERR(infile);
		infile = NULL;
		goto out;
	}

	buf = kmalloc(GFP_KERNEL, PATH_MAX);
	if (buf == NULL) {
		retval = -ENOMEM;
		goto out;
	}

	outfile = filp_open(args->output_file_path,
			    O_WRONLY | O_CREAT | O_TRUNC, 0777);

	if (IS_ERR(outfile)) {
		retval = PTR_ERR(outfile);
		outfile = NULL;
		goto out;
	}

	hash_alg = crypto_alloc_shash("md5", 0, 0);
	if (IS_ERR(hash_alg)) {
		retval = PTR_ERR(hash_alg);
		hash_alg = NULL;
		printk("Line no:%d, Invalid hash algorithm\n", __LINE__);
		goto out;
	}

	desc_size = crypto_shash_descsize(hash_alg) + sizeof(struct shash_desc);
	desc = kmalloc(desc_size, GFP_KERNEL);
	if (desc == NULL) {
		retval = -ENOMEM;
		printk("Line no:%d, Could not allocate memory to desc\n",
		       __LINE__);
		goto out;
	}

	desc->tfm = hash_alg;
	retval = crypto_shash_init(desc);
	if (retval < 0) {
		printk("Could not intialize");
		goto out;
	}

	do {
		no_bytes_read =
			kernel_read(infile, buf, PATH_MAX, &input_file_pos);

		if (no_bytes_read < 0) {
			printk("Could not read from the input file\n");
			goto out;
		}

		if (no_bytes_read == 0)
			break;

		retval = crypto_shash_update(desc, buf, no_bytes_read);

	} while (no_bytes_read > 0);

	retval = crypto_shash_final(desc, file_hash);
	if (retval < 0) {
		printk("Could not fetch final hash value");
		goto out;
	}

	md5_to_hex(hex_file_hash, file_hash);

	no_bytes_written = kernel_write(outfile, hex_file_hash, 2 * DIGEST_SIZE,
					&output_file_pos);

	if (no_bytes_written < 0) {
		printk("Could not write to output file\n");
		goto out;
	}

	printk("File hash:%s\n", hex_file_hash);

out:
	if (buf != NULL)
		kfree(buf);

	if (desc != NULL)
		kfree(desc);

	if (hash_alg != NULL)
		crypto_free_shash(hash_alg);

	if (infile != NULL)
		filp_close(infile, NULL);

	if (outfile != NULL)
		filp_close(outfile, NULL);

	hash_op_cleanup(args);
	job_wrapper->op_status = retval;
	job_wrapper->job_status = COMPLETED;
	return;
}

int get_hashed_key(const unsigned char *key, char *hashed_key, int keylen)
{
	int RETVAL = 0;
	struct crypto_shash *hash_alg;
	struct shash_desc *desc;
	unsigned int desc_size;

	hash_alg = crypto_alloc_shash("md5", 0, 0);
	if (IS_ERR(hash_alg)) {
		RETVAL = PTR_ERR(hash_alg);
		printk("Line no:%d, Invalid hash algorithm\n", __LINE__);
		goto _out1;
	}

	desc_size = crypto_shash_descsize(hash_alg) + sizeof(struct shash_desc);
	desc = kmalloc(desc_size, GFP_KERNEL);
	if (desc == NULL) {
		RETVAL = -ENOMEM;
		printk("Line no:%d, Could not allocate memory to desc\n",
		       __LINE__);
		goto _out2;
	}

	desc->tfm = hash_alg;
	RETVAL = crypto_shash_digest(desc, key, keylen, hashed_key);
	hashed_key[DIGEST_SIZE] = '\0';
	kfree(desc);

_out2:
	crypto_free_shash(hash_alg);
_out1:
	return RETVAL;
}

int remove_file_link(struct file *fl)
{
	int RETVAL = 0;
	struct dentry *file_dentry;

	file_dentry = fl->f_path.dentry;
	inode_lock(file_dentry->d_parent->d_inode);
	RETVAL = vfs_unlink(file_dentry->d_parent->d_inode, file_dentry, NULL);
	inode_unlock(file_dentry->d_parent->d_inode);
	return RETVAL;
}

int replace_file(struct file *source_file, struct file *target_file)
{
	int RETVAL = 0;
	struct path target_file_path = target_file->f_path;
	struct inode *source_parent_dir_inode =
		source_file->f_path.dentry->d_parent->d_inode;

	RETVAL = remove_file_link(target_file);
	if (RETVAL < 0) {
		printk("Line no:%d, Could not delete the file", __LINE__);
		goto _out1;
	}

	RETVAL = vfs_rename(source_parent_dir_inode, source_file->f_path.dentry,
			    source_parent_dir_inode, target_file_path.dentry,
			    NULL, 0);
	if (RETVAL < 0) {
		printk("Line no:%d, Could not rename the file", __LINE__);
	}

_out1:
	return RETVAL;
}

static void var_arg_cleanup(struct var_args *args)
{
	int iterator = 0;
	for (iterator = 0; iterator < args->count; ++iterator) {
		kfree(args->filenames[iterator]);
	}
	kfree(args);
	return;
}

static void enc_dec_op_cleanup(struct enc_dec_args *args)
{
	kfree(args->key);
	kfree(args->input_file_path);
	kfree(args->output_file_path);
	kfree(args);
}

static void concat_op_cleanup(struct concat_files *concat_arg)
{
	int iterator = 0;
	for (iterator = 0; iterator < concat_arg->count; ++iterator) {
		kfree(concat_arg->input_file_paths[iterator]);
	}
	kfree(concat_arg->output_file_path);
	kfree(concat_arg);
}

static void rename_op_cleanup(struct rename_files *rename_args)
{
	int iterator = 0;
	for (iterator = 0; iterator < rename_args->vargs->count; ++iterator) {
		kfree(rename_args->vargs->filenames[iterator]);
		kfree(rename_args->destination_file_paths[iterator]);
	}
	kfree(rename_args->vargs);
	kfree(rename_args);
}

static void cryptocopy(struct work_struct *job)
{
	int RETVAL = 0, success = 0, new_file_created = 0;
	long long int input_file_pos, output_file_pos;
	int no_bytes_read, no_bytes_written, carry, iterator, temp_carry;
	unsigned int infile_mode, outfile_mode;
	struct file *infile = NULL, *outfile = NULL, *temp_file = NULL;
	struct crypto_skcipher *crypto_alg = NULL;
	struct skcipher_request *request = NULL;
	struct scatterlist scatter_list;
	char *buf = NULL, *temp_file_name = NULL;
	unsigned char key[DIGEST_SIZE + 1], hashed_key[DIGEST_SIZE + 1];
	u8 IV[16] = { 48, 48, 48, 48, 48, 48, 48, 48,
		      48, 48, 48, 48, 48, 48, 48, 48 };

	struct work_struct_wrapper *job_wrapper =
		container_of(job, struct work_struct_wrapper, async_job);
	struct enc_dec_args *args = (struct enc_dec_args *)job_wrapper->args;

	msleep(10000);
	if (args->keylen < MIN_KEY_SIZE || args->keylen > MAX_KEY_SIZE) {
		RETVAL = -EKEYREJECTED;
		printk("Line no:%d, Invalid key size. Length of a valid key should be between 6 and 50 characters\n",
		       __LINE__);
		goto out;
	}

	get_hashed_key(args->key, key, args->keylen);

	infile = filp_open(args->input_file_path, O_RDONLY, 0);

	if (IS_ERR(infile)) {
		RETVAL = PTR_ERR(infile);
		infile = NULL;
		printk("Line no:%d, Could not fetch file %s. Err:%d\n",
		       __LINE__, args->input_file_path, RETVAL);
		goto out;
	}

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);

	if (buf == NULL) {
		RETVAL = -ENOMEM;
		printk("Line no:%d, Could not allocate memory to buffer\n",
		       __LINE__);
		goto out;
	}

	outfile = filp_open(args->output_file_path, O_WRONLY, 0777);

	if (IS_ERR(outfile)) {
		if (PTR_ERR(outfile) == -ENOENT) {
			outfile = filp_open(args->output_file_path,
					    O_WRONLY | O_CREAT, 0777);

			if (IS_ERR(outfile)) {
				RETVAL = PTR_ERR(outfile);
				outfile = NULL;
				printk("Line no:%d, Could not create new file with name %s",
				       __LINE__, args->output_file_path);
				goto out;
			}

			new_file_created = 1;

		} else {
			RETVAL = PTR_ERR(outfile);
			outfile = NULL;
			printk("Line no:%d, Could not fetch %s", __LINE__,
			       args->output_file_path);
			goto out;
		}

	} else {
		if (infile->f_inode == outfile->f_inode) {
			printk("Line no:%d, Cannot perform in place operation on the file",
			       __LINE__);
			RETVAL = -EPERM;
			goto out;
		}

		infile_mode = get_file_mode(infile);
		outfile_mode = get_file_mode(outfile);

		if ((infile_mode & outfile_mode) != infile_mode) {
			printk("Line no:%d, Output file should at least have same permissions as input file",
			       __LINE__);
			RETVAL = -EACCES;
			goto out;
		}
	}

	if (new_file_created) {
		temp_file = outfile;
	} else {
		temp_file_name =
			kmalloc(strlen(args->output_file_path) + 5, GFP_KERNEL);

		if (temp_file_name == NULL) {
			printk("Line no:%d, Could not create temp file name",
			       __LINE__);
			RETVAL = -ENOMEM;
			goto out;
		}

		strcpy(temp_file_name, args->output_file_path);
		strcat(temp_file_name, ".tmp");
		temp_file = filp_open(temp_file_name, O_WRONLY | O_CREAT, 0777);

		if (IS_ERR(temp_file)) {
			RETVAL = PTR_ERR(temp_file);
			temp_file = NULL;
			printk("Line no:%d, Could not create temp file to write",
			       __LINE__);
			goto out;
		}
	}

	crypto_alg = crypto_alloc_skcipher("ctr(aes)", 0, 0);

	if (IS_ERR(crypto_alg)) {
		RETVAL = PTR_ERR(crypto_alg);
		crypto_alg = NULL;
		goto out;
	}

	RETVAL = crypto_skcipher_setkey(crypto_alg, key, DIGEST_SIZE);

	if (RETVAL) {
		printk("Line no:%d, Could not set key\n", __LINE__);
		goto out;
	}

	request = skcipher_request_alloc(crypto_alg, GFP_KERNEL);

	if (IS_ERR(request)) {
		RETVAL = PTR_ERR(request);
		request = NULL;
		printk("Line no:%d, Could not create request object\n",
		       __LINE__);
		goto out;
	}

	input_file_pos = 0;
	output_file_pos = 0;

	RETVAL = get_hashed_key(key, hashed_key, DIGEST_SIZE);

	if (RETVAL) {
		printk("Line no:%d, Could not calculate hash value\n",
		       __LINE__);
		goto out;
	}

	if (args->flag & 1) {
		no_bytes_written = kernel_write(temp_file, hashed_key,
						DIGEST_SIZE, &output_file_pos);

		if (no_bytes_written < 0) {
			RETVAL = no_bytes_written;
			printk("Line no:%d, Could not copy hashed key\n",
			       __LINE__);
			goto out;
		}

	} else {
		no_bytes_read =
			kernel_read(infile, buf, DIGEST_SIZE, &input_file_pos);

		if (no_bytes_read < 0) {
			RETVAL = no_bytes_read;
			printk("Line no:%d, Could not fetch hashed key\n",
			       __LINE__);
			goto out;
		}

		if (no_bytes_read < DIGEST_SIZE) {
			RETVAL = -EIO;
			printk("Line no:%d, File does not contain enough content to verify key\n",
			       __LINE__);
			goto out;
		}

		buf[DIGEST_SIZE] = '\0';
		if (strcmp(buf, hashed_key)) {
			RETVAL = -EKEYREJECTED;
			printk("Line no:%d, Key invalid for decryption\n",
			       __LINE__);
			goto out;
		}
	}

	do {
		no_bytes_read =
			kernel_read(infile, buf, PAGE_SIZE, &input_file_pos);

		if (no_bytes_read < 0) {
			RETVAL = no_bytes_read;
			printk("Line no:%d, Could not read content from file\n",
			       __LINE__);
			goto out;
		}

		sg_init_one(&scatter_list, buf, no_bytes_read);
		skcipher_request_set_crypt(request, &scatter_list,
					   &scatter_list, no_bytes_read, IV);

		if (args->flag & 1)
			RETVAL = crypto_skcipher_encrypt(request);
		else
			RETVAL = crypto_skcipher_decrypt(request);

		if (RETVAL) {
			printk("Line no:%d, Could not perform required operation\n",
			       __LINE__);
			goto out;
		}

		no_bytes_written = kernel_write(temp_file, buf, no_bytes_read,
						&output_file_pos);

		if (no_bytes_written < 0) {
			RETVAL = no_bytes_written;
			printk("Line no:%d, Could not write content to file\n",
			       __LINE__);
			goto out;
		}

		carry = (IV[15] + 1) / 256;
		IV[15] = (IV[15] + 1) % 256;
		iterator = 14;

		while (iterator >= 0 && carry) {
			temp_carry = carry;
			IV[iterator] = (IV[iterator] + temp_carry) % 256;
			carry = (IV[iterator] + temp_carry) / 256;
			--iterator;
		}

	} while (no_bytes_read > 0);

	if (i_size_read(infile->f_inode) > input_file_pos) {
		RETVAL = -EIO;
		printk("Line no: %d, Could not copy entire input file\n",
		       __LINE__);
		goto out;
	}
	success = 1;
	printk("ENC_DEC SUCCESSFUL");

out:
	if (success) {
		if (!new_file_created) {
			replace_file(temp_file, outfile);
			filp_close(temp_file, NULL);
		}
	} else if (new_file_created) {
		remove_file_link(outfile);
	} else if (temp_file_name != NULL) {
		kfree(temp_file_name);
		if (temp_file != NULL) {
			remove_file_link(temp_file);
			filp_close(temp_file, NULL);
		}
	}

	if (request != NULL)
		skcipher_request_free(request);
	if (crypto_alg != NULL)
		crypto_free_skcipher(crypto_alg);
	if (outfile != NULL)
		filp_close(outfile, NULL);
	if (buf != NULL)
		kfree(buf);
	if (infile != NULL)
		filp_close(infile, NULL);
	enc_dec_op_cleanup(args);
	job_wrapper->op_status = RETVAL;
	job_wrapper->job_status = COMPLETED;
	return;
}

static void delete_func(struct work_struct *job)
{
	int iterator, status = 0;
	struct file *input_file = NULL;
	struct work_struct_wrapper *job_wrapper =
		container_of(job, struct work_struct_wrapper, async_job);
	struct var_args *args = (struct var_args *)job_wrapper->args;
	msleep(10000);

	for (iterator = 0; iterator < args->count; iterator++) {
		input_file = filp_open(args->filenames[iterator], O_RDONLY, 0);
		if (IS_ERR(input_file)) {
			job_wrapper->status[iterator] = PTR_ERR(input_file);
			input_file = NULL;
			printk("Line no:%d, Could not fetch file %s. Err:%d\n",
			       __LINE__, args->filenames[iterator],
			       job_wrapper->status[iterator]);
			continue;
		}

		status = remove_file_link(input_file);
		if (status != 0) {
			job_wrapper->status[iterator] = status;
			filp_close(input_file, NULL);
			input_file = NULL;
			continue;
		}

		if (input_file) {
			if (!IS_ERR(input_file)) {
				filp_close(input_file, NULL);
				input_file = NULL;
			}
		}

		job_wrapper->status[iterator] = status;
	}

	printk("DELETE SUCCESSFUL\n");

	if (input_file) {
		if (!IS_ERR(input_file)) {
			filp_close(input_file, NULL);
		}
	}

	job_wrapper->job_status = COMPLETED;
	return;
}

static void concatenate_func(struct work_struct *job)
{
	int iter, input_length, new_file_created = 0;
	int read_bytes, write_bytes;
	int status = 0;
	char *rw_buffer = NULL, *temp_file_name = NULL;
	struct file *input_file = NULL, *output_file = NULL, *temp_file = NULL;
	struct work_struct_wrapper *job_wrapper =
		container_of(job, struct work_struct_wrapper, async_job);
	struct concat_files *args = (struct concat_files *)job_wrapper->args;
	msleep(10000);

	rw_buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (rw_buffer == NULL) {
		status = -ENOMEM;
		printk("Line no:%d, Could not allocate memory to buffer\n",
		       __LINE__);
		goto _out1;
	}

	output_file = filp_open(args->output_file_path, O_WRONLY, 0777);

	if (IS_ERR(output_file)) {
		if (PTR_ERR(output_file) == -ENOENT) {
			output_file = filp_open(args->output_file_path,
						O_WRONLY | O_CREAT, 0777);

			if (IS_ERR(output_file)) {
				status = PTR_ERR(output_file);
				output_file = NULL;
				printk("Line no:%d, Could not create new file with name %s",
				       __LINE__, args->output_file_path);
				goto _out1;
			}

			new_file_created = 1;

		} else {
			status = PTR_ERR(output_file);
			output_file = NULL;
			printk("Line no:%d, Could not fetch %s", __LINE__,
			       args->output_file_path);
			goto _out1;
		}
	}

	if (new_file_created) {
		temp_file = output_file;
	} else {
		temp_file_name =
			kmalloc(strlen(args->output_file_path) + 5, GFP_KERNEL);

		if (temp_file_name == NULL) {
			printk("Line no:%d, Could not create temp file name",
			       __LINE__);
			status = -ENOMEM;
			goto _out1;
		}

		strcpy(temp_file_name, args->output_file_path);
		strcat(temp_file_name, ".tmp");
		temp_file = filp_open(temp_file_name, O_WRONLY | O_CREAT, 0666);

		if (IS_ERR(temp_file)) {
			status = PTR_ERR(temp_file);
			temp_file = NULL;
			printk("Line no:%d, Could not create temp file to write",
			       __LINE__);
			goto _out1;
		}
	}

	temp_file->f_pos = 0;

	for (iter = 0; iter < args->count; iter++) {
		input_file =
			filp_open(args->input_file_paths[iter], O_RDONLY, 0);

		if (!input_file || IS_ERR(input_file)) {
			input_file = NULL;
			printk("Line no:%d, Could not fetch file %s.\n",
			       __LINE__, args->input_file_paths[iter]);
			status = -ENOENT;
			goto _out1;
		}

		if (input_file->f_inode == temp_file->f_inode) {
			printk("Line no:%d, Cannot perform in place operation on the file",
			       __LINE__);
			status = -EPERM;
			goto _out1;
		}

		input_file->f_pos = 0;
		input_length = input_file->f_inode->i_size;

		while (input_length > 0) {
			read_bytes =
				kernel_read(input_file, rw_buffer, PAGE_SIZE,
					    &(input_file->f_pos));

			if (read_bytes < 0) {
				printk("Line no:%d, Could not read content from file\n",
				       __LINE__);
				status = read_bytes;
				goto _out1;
			}

			write_bytes =
				kernel_write(temp_file, rw_buffer, read_bytes,
					     &(temp_file->f_pos));

			if (write_bytes < 0) {
				printk("Line no:%d, Could not write bytes\n",
				       __LINE__);
				status = write_bytes;
				goto _out1;
			}

			input_length -= read_bytes;
		}

		if (input_file) {
			if (!IS_ERR(input_file)) {
				filp_close(input_file, NULL);
				input_file = NULL;
			}
		}
	}

	printk("CONCATENATE SUCCESSFUL\n");
	goto _out1;

_out1:
	if (status == 0) {
		if (!new_file_created) {
			replace_file(temp_file, output_file);
			filp_close(temp_file, NULL);
		}
	} else if (new_file_created) {
		remove_file_link(output_file);
	} else if (temp_file_name != NULL) {
		kfree(temp_file_name);
		if (temp_file != NULL) {
			remove_file_link(temp_file);
			filp_close(temp_file, NULL);
		}
	}

	if (input_file) {
		if (!IS_ERR(input_file)) {
			filp_close(input_file, NULL);
		}
	}

	if (output_file) {
		if (!IS_ERR(output_file)) {
			filp_close(output_file, NULL);
		}
	}

	if (rw_buffer != NULL)
		kfree(rw_buffer);

	concat_op_cleanup(args);
	job_wrapper->op_status = status;
	job_wrapper->job_status = COMPLETED;
	return;
}

static void rename_func(struct work_struct *job)
{
	int iterator, status = 0;
	struct file *input_file = NULL, *output_file = NULL;
	struct work_struct_wrapper *job_wrapper =
		container_of(job, struct work_struct_wrapper, async_job);
	struct rename_files *args = (struct rename_files *)job_wrapper->args;
	struct var_args *vargs = (struct var_args *)args->vargs;
	msleep(10000);

	for (iterator = 0; iterator < vargs->count; ++iterator) {
		input_file = filp_open(vargs->filenames[iterator], O_RDONLY, 0);
		if (!input_file || IS_ERR(input_file)) {
			input_file = NULL;
			job_wrapper->status[iterator] = -ENOENT;
			printk("Line no:%d, Could not fetch file %s.\n",
			       __LINE__, vargs->filenames[iterator]);
			continue;
		}

		output_file = filp_open(args->destination_file_paths[iterator],
					O_WRONLY | O_CREAT | O_TRUNC, 0777);
		if (!output_file || IS_ERR(output_file)) {
			output_file = NULL;
			job_wrapper->status[iterator] = -ENOENT;
			printk("Line no:%d, Could not fetch output file %s.\n",
			       __LINE__,
			       args->destination_file_paths[iterator]);
			filp_close(input_file, NULL);
			input_file = NULL;
			continue;
		}

		status = replace_file(input_file, output_file);
		if (status != 0) {
			job_wrapper->status[iterator] = status;
			filp_close(input_file, NULL);
			input_file = NULL;
			filp_close(output_file, NULL);
			output_file = NULL;
			continue;
		}

		if (input_file) {
			if (!IS_ERR(input_file)) {
				filp_close(input_file, NULL);
				input_file = NULL;
			}
		}

		if (output_file) {
			if (!IS_ERR(output_file)) {
				filp_close(output_file, NULL);
				output_file = NULL;
			}
		}

		job_wrapper->status[iterator] = status;
	}

	printk("RENAME SUCCESSFUL\n");

	if (input_file) {
		if (!IS_ERR(input_file)) {
			filp_close(input_file, NULL);
		}
	}

	if (output_file) {
		if (!IS_ERR(output_file)) {
			filp_close(output_file, NULL);
		}
	}

	job_wrapper->job_status = COMPLETED;
	return;
}

int get_stat(struct file *input_file, struct file *output_file,
	     struct kstat *file_stat)
{
	int retval = 0, j = 0;
	int write_bytes;
	char *buf = NULL;
	struct rtc_time tm_atime;
	struct rtc_time tm_mtime;
	struct rtc_time tm_ctime;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		retval = -ENOMEM;
		printk("Line no:%d, Could not allocate memory.\n", __LINE__);
		goto out_1;
	}

	memset(buf, 0, PAGE_SIZE);

	j = 0;
	output_file->f_pos = 0;
	j += sprintf(buf + j, "ID OF DEVICE CONTAINING FILE: %d\n",
		     file_stat->dev);
	j += sprintf(buf + j, "INODE NUMBER: %llu\n", file_stat->ino);
	j += sprintf(buf + j, "FILE TYPE AND MODE: %o\n", file_stat->mode);
	j += sprintf(buf + j, "NUMBER OF HARD LINKS: %u\n", file_stat->nlink);
	j += sprintf(buf + j, "USER ID OF OWNER: %d\n", file_stat->uid.val);
	j += sprintf(buf + j, "GROUP ID OF OWNER: %d\n", file_stat->gid.val);
	j += sprintf(buf + j, "Device ID (if special file): %d\n",
		     file_stat->rdev);
	j += sprintf(buf + j, "FILE SIZE (in bytes): %lld\n", file_stat->size);
	j += sprintf(buf + j, "BLOCK SIZE FOR FILESYSTEM I/O: %d\n",
		     file_stat->blksize);
	j += sprintf(buf + j, "NUMBER OF 512B BLOCKS ALLOCATED: %lld\n",
		     file_stat->blocks);

	rtc_time_to_tm(file_stat->atime.tv_sec, &tm_atime);
	j += sprintf(buf + j, "TIME OF LAST ACCESS: "); //
	j += sprintf(buf + j, "%d-%02d-%02d-%02d:%02d\n",
		     tm_atime.tm_year + 1900, tm_atime.tm_mon + 1,
		     tm_atime.tm_mday, tm_atime.tm_hour, tm_atime.tm_min);

	rtc_time_to_tm(file_stat->mtime.tv_sec, &tm_mtime);
	j += sprintf(buf + j, "TIME OF LAST MODIFICATION: "); //
	j += sprintf(buf + j, "%d-%02d-%02d-%02d:%02d\n",
		     tm_mtime.tm_year + 1900, tm_mtime.tm_mon + 1,
		     tm_mtime.tm_mday, tm_mtime.tm_hour, tm_mtime.tm_min);

	rtc_time_to_tm(file_stat->ctime.tv_sec, &tm_ctime);
	j += sprintf(buf + j, "TIME OF LAST STATUS CHANGE: "); //
	j += sprintf(buf + j, "%d-%02d-%02d-%02d:%02d\n",
		     tm_ctime.tm_year + 1900, tm_ctime.tm_mon + 1,
		     tm_ctime.tm_mday, tm_ctime.tm_hour, tm_ctime.tm_min);

	write_bytes = kernel_write(output_file, buf, j, &(output_file->f_pos));
	if (write_bytes < 0) {
		retval = write_bytes;
		goto out_1;
	}

out_1:
	kfree(buf);
	return retval;
}

static void stat_func(struct work_struct *job)
{
	int iterator, status = 0;
	struct file *input_file = NULL, *output_file = NULL;
	struct work_struct_wrapper *job_wrapper =
		container_of(job, struct work_struct_wrapper, async_job);
	struct rename_files *args = (struct rename_files *)job_wrapper->args;
	struct var_args *vargs = (struct var_args *)args->vargs;
	struct kstat *file_stat = NULL;
	msleep(10000);

	file_stat = kmalloc(sizeof(struct kstat), GFP_KERNEL);
	if (!file_stat) {
		printk("Line no:%d, Could not allocate memory.\n", __LINE__);
		goto _out1;
	}

	for (iterator = 0; iterator < vargs->count; ++iterator) {
		memset(file_stat, 0, sizeof(struct kstat));

		status = vfs_stat(vargs->filenames[iterator], file_stat);
		if (status < 0) {
			job_wrapper->status[iterator] = status;
			printk("Line no:%d, Could not perform stat.\n",
			       __LINE__);
			continue;
		}

		input_file = filp_open(vargs->filenames[iterator], O_RDONLY, 0);

		if (!input_file || IS_ERR(input_file)) {
			input_file = NULL;
			job_wrapper->status[iterator] = -ENOENT;
			printk("Line no:%d, Could not fetch file %s.\n",
			       __LINE__, vargs->filenames[iterator]);
			continue;
		}

		output_file = filp_open(args->destination_file_paths[iterator],
					O_WRONLY | O_CREAT | O_TRUNC, 0777);

		if (!output_file || IS_ERR(output_file)) {
			output_file = NULL;
			job_wrapper->status[iterator] = -ENOENT;
			printk("Line no:%d, Could not fetch output file %s.\n",
			       __LINE__,
			       args->destination_file_paths[iterator]);
			filp_close(input_file, NULL);
			input_file = NULL;
			continue;
		}

		status = get_stat(input_file, output_file, file_stat);
		if (status != 0) {
			printk("Line no:%d, Could not write stat to output file.\n",
			       __LINE__);
			job_wrapper->status[iterator] = status;
			filp_close(input_file, NULL);
			input_file = NULL;
			filp_close(output_file, NULL);
			output_file = NULL;
			continue;
		}

		if (input_file) {
			if (!IS_ERR(input_file)) {
				filp_close(input_file, NULL);
				input_file = NULL;
			}
		}

		if (output_file) {
			if (!IS_ERR(output_file)) {
				filp_close(output_file, NULL);
				output_file = NULL;
			}
		}

		job_wrapper->status[iterator] = status;
	}

	printk("STAT SUCCESSFUL\n");

_out1:
	if (file_stat != NULL) {
		kfree(file_stat);
	}

	if (input_file) {
		if (!IS_ERR(input_file)) {
			filp_close(input_file, NULL);
		}
	}

	if (output_file) {
		if (!IS_ERR(output_file)) {
			filp_close(output_file, NULL);
		}
	}

	job_wrapper->job_status = COMPLETED;
	return;
}