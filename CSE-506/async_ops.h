// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 1998-2020 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2020 Stony Brook University
 * Copyright (c) 2003-2020 The Research Foundation of SUNY
 */

#ifndef _ASYNCOPS_H_
#define _ASYNCOPS_H_

#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/sched.h>
#include <linux/xattr.h>

#define OP_MAX_ARGS 6
#define COMMAND_BASIC_ARGS 2
#define USER_ARGS_OFFSET 2

#define ROOT_USER_ID 0

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

#define IOCTL_DELETE _IOR('a', 'a', struct var_args *)

#define IOCTL_GET_ACTIVE_JOBS _IOW('a', 'b', void *)

#define IOCTL_PRIORITY_BOOST _IOR('a', 'c', int *)

#define IOCTL_DELETE_JOB _IOR('a', 'd', int)

#define IOCTL_ENC_DEC _IOR('a', 'e', struct enc_dec_args *)

#define IOCTL_GET_STATUS _IOWR('a', 'f', void *)

#define IOCTL_CONCATENATE _IOR('a', 'g', struct concat_files *)

#define IOCTL_RENAME _IOR('a', 'h', struct rename_files *)

#define IOCTL_COMP_DEC _IOR('a', 'i', struct compress_args *)

#define IOCTL_GET_COMPLETED_JOBS _IOW('a', 'j', void *)

#define IOCTL_STAT _IOR('a', 'k', struct rename_files *)

#define IOCTL_HASH _IOR('a', 'l', struct hash_args *)

// max pending/running jobs allowed in a queue
#define MAX_ACTIVE_JOBS 10
#define MAX_COMPLETED_JOBS_COUNT 10

// status of job
#define PENDING 0
#define RUNNING 1
#define COMPLETED 2

// priority of job
#define PRIORITY_LOW 1
#define PRIORITY_HIGH 2

//OPERATION MACROS
#define DELETE_OP 0
#define RENAME_OP 1
#define STAT_OP 2
#define CONCAT_OP 3
#define HASH_OP 4
#define ENC_DEC_OP 5
#define COMP_DEC_OP 6

#define MAX_NUMBER_OF_FILES 6

// string operation macros
#define DELETE_OP_STR "delete"
#define CONCAT_OP_STR "concatenate"
#define RENAME_OP_STR "rename"
#define STAT_OP_STR "stat"
#define COMP_DEC_STR "comp"
#define ENC_DEC_STR "crypt"
#define HASH_OP_STR "hash"

// string queue operation macros
#define LIST_JOBS_STR "list_jobs"
#define PRIORITY_BOOST_STR "priority_boost"
#define DELETE_JOB_STR "delete_job"
#define POLL_STATUS "get_status"
#define LIST_COMPLETED_JOBS "get_completed_jobs"

// cyrptography operation macros
#define DIGEST_SIZE 16
#define MAX_KEY_SIZE 50
#define MIN_KEY_SIZE 7

// argument requirement
#define USER_ARGS_OFFSET 2
#define MIN_ARGS_CONCAT 5

#define NUMBER_OF_STAT_INFO 13
#define INPUT_FILE 0
#define OUTPUT_FILE 1

struct var_args {
	int count;
	char *filenames[MAX_NUMBER_OF_FILES];
	int priority;
};

struct enc_dec_args {
	char *input_file_path;
	char *output_file_path;
	char *key;
	int keylen;
	int flag;
	int priority;
};

struct rename_files {
	struct var_args *vargs;
	char *destination_file_paths[MAX_NUMBER_OF_FILES];
};

struct concat_files {
	int count;
	char *input_file_paths[MAX_NUMBER_OF_FILES];
	char *output_file_path;
	int priority;
};

struct hash_args {
	char *input_file_path;
	char *file_hash;
	char *output_file_path;
	int priority;
};

struct compress_args {
	char *input_file_path;
	char *output_file_path;
	int flag;
	int priority;
};

struct job {
	int user_id;
	int job_id;
	int job_status;
	int operation;
	int priority;
	time_t time_on_queue;
};

struct list_all_jobs {
	int count;
	struct job jobs[MAX_ACTIVE_JOBS];
};

struct list_completed_jobs {
	int count;
	struct job jobs[MAX_COMPLETED_JOBS_COUNT];
};

struct poll_status {
	int job_id;
	int job_status;
	int user_id;
	int count;
	char filenames[MAX_NUMBER_OF_FILES][PATH_MAX];
	int status[MAX_NUMBER_OF_FILES];
	int op;
	int op_status;
};

#endif