#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include "async_ops.h"

char *get_path(char *given_path, char *actualpath, int operation, int file_type)
{
	char *result_path = NULL;
	char *ptr = NULL;

	ptr = realpath(given_path, actualpath);

	if (file_type == OUTPUT_FILE) {
		if (ptr == NULL) {
			result_path = getcwd(actualpath, sizeof(actualpath));
			result_path = actualpath;

		} else {
			result_path = ptr;
		}
	}

	else {
		if (ptr != NULL) {
			result_path = ptr;

		} else {
			result_path = getcwd(actualpath, sizeof(actualpath));
			result_path = actualpath;
		}
	}

	return result_path;
}

int get_unlink_args(int argc, const char *argv[], struct var_args *args)
{
	int nfiles = 0, option, rc = 0, flag = 0, i, priority = PRIORITY_LOW;
	char *getPath[OP_MAX_ARGS];
	optind = 2;
	while ((option = getopt(argc, (char *const *)argv, "Phn:i:")) != -1) {
		switch (option) {
		case 'n':
			nfiles = atoi(optarg);
			break;
		case 'i':
			args->filenames[0] = (char *)optarg;
			flag |= 1;
			break;
		case 'h':
			printf("Usage: %s %s -n N -i file1 file2 .. fileN\n",
			       argv[0], argv[1]);
			printf("Options\n");
			printf("-n\t\t for number of files to delete\n");
			printf("-i\t\t for files\n");
			rc = -1;
			goto out;
			break;
		case 'P':
			priority = PRIORITY_HIGH;
			break;
		case ':':
			printf("Option -%c requires an argument\n", optopt);
			rc = -1;
			goto out;
			break;
		case '?':
			printf("Option -%c not recognized\n", optopt);
			rc = -1;
			goto out;
		}
	}

	if (nfiles == 0 || flag != 1) {
		printf("Usage: %s %s -n N -i file1 file2 .. fileN\n", argv[0],
		       argv[1]);
		rc = -1;
		goto out;
	}

	if (nfiles > MAX_NUMBER_OF_FILES) {
		printf("Upto %d input files allowed\n", MAX_NUMBER_OF_FILES);
		rc = -1;
		goto out;
	}

	if (argc - optind != nfiles - 1) {
		printf("Usage: %s %s -n N -i file1 file2 .. fileN\n", argv[0],
		       argv[1]);
		rc = -1;
		goto out;
	}

	for (i = 1; i <= nfiles - 1; ++i) {
		args->filenames[i] = (char *)argv[optind++];
	}

	args->count = nfiles;

	for (i = 0; i < nfiles; ++i) {
		getPath[i] = (char *)malloc(sizeof(char) * PATH_MAX);
		args->filenames[i] = get_path(args->filenames[i], getPath[i],
					      DELETE_OP, INPUT_FILE);
	}
	args->priority = priority;
out:
	return rc;
}

int get_concatenate_args(int argc, const char *argv[],
			 struct concat_files *args)
{
	int nfiles = 0, option, rc = 0, flag = 0, i, priority = PRIORITY_LOW;
	char *getPath[OP_MAX_ARGS + 1];
	optind = 2;
	while ((option = getopt(argc, (char *const *)argv, ":Pn:i:o:")) != -1) {
		switch (option) {
		case 'n':
			nfiles = atoi(optarg);
			break;
		case 'i':
			args->input_file_paths[0] = (char *)optarg;
			flag |= 1;
			break;
		case 'o':
			args->output_file_path = (char *)optarg;
			flag |= 2;
			break;
		case 'P':
			priority = PRIORITY_HIGH;
			break;
		case ':':
			printf("Option -%c requires an argument\n", optopt);
			rc = -1;
			goto out;
			break;
		case '?':
			printf("Option -%c not recognized\n", optopt);
			rc = -1;
			goto out;
		}
	}

	if (nfiles == 0 || flag != 3) {
		printf("Usage: %s %s -n N -i file1 file2 .. fileN -o output_file\n",
		       argv[0], argv[1]);
		rc = -1;
		goto out;
	}

	if (nfiles > MAX_NUMBER_OF_FILES) {
		printf("Upto %d input files allowed\n", MAX_NUMBER_OF_FILES);
		rc = -1;
		goto out;
	}

	if (argc - optind != nfiles - 1) {
		printf("Usage: %s %s -n N -i file1 file2 .. fileN -o output_file\n",
		       argv[0], argv[1]);
		printf("%d", __LINE__);
		rc = -1;
		goto out;
	}

	for (i = 1; i <= nfiles - 1; ++i) {
		args->input_file_paths[i] = (char *)argv[optind++];
	}

	args->count = nfiles;

	for (i = 0; i < nfiles; ++i) {
		getPath[i] = (char *)malloc(sizeof(char) * PATH_MAX);
		args->input_file_paths[i] =
			get_path(args->input_file_paths[i], getPath[i],
				 CONCAT_OP, INPUT_FILE);
	}

	getPath[i] = (char *)malloc(sizeof(char) * PATH_MAX);
	args->output_file_path = get_path(args->output_file_path, getPath[i],
					  CONCAT_OP, OUTPUT_FILE);
	args->priority = priority;

out:
	return rc;
}

int get_rename_args(int argc, const char *argv[], struct rename_files *args,
		    struct var_args *vargs)
{
	int nfiles = 0, option, rc = 0, flag = 0, i, priority = PRIORITY_LOW;
	char *getPath[OP_MAX_ARGS * 2];
	optind = 2;
	while ((option = getopt(argc, (char *const *)argv, ":Pn:i:o:")) != -1) {
		switch (option) {
		case 'n':
			nfiles = atoi(optarg);
			break;
		case 'i':
			vargs->filenames[0] = (char *)optarg;
			flag |= 1;
			break;
		case 'o':
			args->destination_file_paths[0] = (char *)optarg;
			flag |= 2;
			break;
		case 'P':
			priority = PRIORITY_HIGH;
			break;
		case ':':
			printf("Option -%c requires an argument\n", optopt);
			rc = -1;
			goto out;
			break;
		case '?':
			printf("Option -%c not recognized\n", optopt);
			rc = -1;
			goto out;
		}
	}

	if (nfiles == 0 || flag != 3) {
		printf("Usage: %s %s -n N -i infile1 infile2 .. infileN -o outfile1 outfile2 .. outfileN\n",
		       argv[0], argv[1]);
		rc = -1;
		goto out;
	}

	if (nfiles > MAX_NUMBER_OF_FILES) {
		printf("Upto %d input files allowed\n", MAX_NUMBER_OF_FILES);
		rc = -1;
		goto out;
	}

	if (argc - optind != 2 * (nfiles - 1)) {
		printf("Usage: %s %s -n N -i infile1 infile2 .. infileN -o outfile1 outfile2 .. outfileN\n",
		       argv[0], argv[1]);
		printf("%d", __LINE__);
		rc = -1;
		goto out;
	}

	for (i = 1; i <= nfiles - 1; ++i) {
		vargs->filenames[i] = (char *)argv[optind++];
	}

	for (i = 1; i <= nfiles - 1; ++i) {
		args->destination_file_paths[i] = (char *)argv[optind++];
	}

	vargs->count = nfiles;
	vargs->priority = priority;
	args->vargs = vargs;

	for (i = 0; i < nfiles; ++i) {
		getPath[i] = (char *)malloc(sizeof(char) * PATH_MAX);
		vargs->filenames[i] = get_path(vargs->filenames[i], getPath[i],
					       RENAME_OP, INPUT_FILE);

		getPath[i + nfiles] = (char *)malloc(sizeof(char) * PATH_MAX);
		args->destination_file_paths[i] =
			get_path(args->destination_file_paths[i],
				 getPath[i + nfiles], RENAME_OP, OUTPUT_FILE);
	}

out:
	return rc;
}

int get_hash_args(int argc, const char *argv[], struct hash_args *args)
{
	int rc = 0, priority = PRIORITY_LOW, option;
	char *getPath[2];

	optind = 2;
	while ((option = getopt(argc, (char *const *)argv, ":P")) != -1) {
		switch (option) {
		case 'P':
			priority = PRIORITY_HIGH;
			break;
		case ':':
			printf("Option -%c requires an argument\n", optopt);
			rc = -1;
			goto out;
			break;
		case '?':
			printf("Option -%c not recognized\n", optopt);
			rc = -1;
			goto out;
		}
	}

	if (argc - optind != 2) {
		printf("Usage: %s %s infile outfile\n", argv[0], argv[1]);
		rc = -1;
		return rc;
	}

	args->input_file_path = (char *)argv[optind++];
	args->output_file_path = (char *)argv[optind++];

	getPath[0] = (char *)malloc(sizeof(char) * PATH_MAX);
	args->input_file_path = get_path(args->input_file_path, getPath[0],
					 HASH_OP, INPUT_FILE);

	getPath[1] = (char *)malloc(sizeof(char) * PATH_MAX);
	args->output_file_path = get_path(args->output_file_path, getPath[1],
					  HASH_OP, OUTPUT_FILE);

	args->priority = priority;

out:
	return rc;
}

int get_comp_args(int argc, const char *argv[], struct compress_args *args)
{
	int rc = 0, flag = 0, option, priority = PRIORITY_LOW;
	char *getPath[2];

	while ((option = getopt(argc, (char *const *)argv, ":Phcd")) != -1) {
		switch (option) {
		case 'c':
			flag |= 1;
			break;
		case 'd':
			flag |= 2;
			break;
		case 'h':
			printf("Usage: %s %s {-c|-d} infile outfile\n", argv[0],
			       argv[1]);
			printf("Options\n");
			printf("-c\t\t for compression\n");
			printf("-d\t\t for decompression\n");
			rc = -1;
			goto out;
			break;
		case 'P':
			priority = PRIORITY_HIGH;
			break;
		case '?':
			printf("Option -%c not recognized\n", optopt);
			rc = -1;
			goto out;
		}
	}

	if (flag != 1 && flag != 2) {
		printf("Usage: %s %s {-c|-d} infile outfile\n", argv[0],
		       argv[1]);
	}

	if (argc - optind != 2) {
		printf("Usage: %s %s {-c|-d} infile outfile\n", argv[0],
		       argv[1]);
		rc = -1;
		return rc;
	}

	args->input_file_path = (char *)argv[optind];
	optind++;
	args->output_file_path = (char *)argv[optind];

	getPath[0] = (char *)malloc(sizeof(char) * PATH_MAX);
	args->input_file_path = get_path(args->input_file_path, getPath[0],
					 COMP_DEC_OP, INPUT_FILE);

	getPath[1] = (char *)malloc(sizeof(char) * PATH_MAX);
	args->output_file_path = get_path(args->output_file_path, getPath[1],
					  COMP_DEC_OP, OUTPUT_FILE);

	args->flag = flag;
	args->priority = priority;
out:
	return rc;
}

int get_enc_dec_args(int argc, const char *argv[], struct enc_dec_args *args)
{
	int rc = 0, option, flag = 0, priority = PRIORITY_LOW;
	int password_mentioned = 0;
	char *getPath[2];
	args->key = NULL;
	args->keylen = 0;

	while ((option = getopt(argc, (char *const *)argv, ":Phcdep:")) != -1) {
		switch (option) {
		case 'e':
			flag |= 1;
			break;
		case 'd':
			flag |= 2;
			break;
		case 'h':
			printf("Usage: %s %s {-d|-e} -p passphrase infile outfile\n",
			       argv[0], argv[1]);
			printf("Options\n");
			printf("-e\t\t for encryption\n");
			printf("-d\t\t for decrpytion\n");
			printf("-p\t\t for password phrase\n");
			rc = -1;
			goto out;
			break;
		case 'p':
			args->key = (char *)optarg;
			password_mentioned = 1;
			break;
		case 'P':
			priority = PRIORITY_HIGH;
			break;
		case ':':
			printf("Option -%c requires an argument\n", optopt);
			rc = -1;
			goto out;
		case '?':
			printf("Option -%c not recognized\n", optopt);
			rc = -1;
			goto out;
		}
	}

	if (flag == 0 || (flag & (flag - 1))) {
		printf("Usage: %s %s {-d|-e} -p passphrase infile outfile\n",
		       argv[0], argv[1]);
		rc = -1;
		goto out;
	}

	if (!password_mentioned) {
		printf("Options -e|-d require [-p passphrase] argument\n");
		rc = -1;
		goto out;
	}

	if (argc - optind != 2) {
		printf("Usage: %s %s {-d|-e} -p passphrase infile outfile\n",
		       argv[0], argv[1]);
		rc = -1;
		goto out;
	}

	args->input_file_path = (char *)argv[optind];
	optind++;
	args->output_file_path = (char *)argv[optind];

	getPath[0] = (char *)malloc(sizeof(char) * PATH_MAX);
	args->input_file_path = get_path(args->input_file_path, getPath[0],
					 ENC_DEC_OP, INPUT_FILE);

	getPath[1] = (char *)malloc(sizeof(char) * PATH_MAX);
	args->output_file_path = get_path(args->output_file_path, getPath[1],
					  ENC_DEC_OP, OUTPUT_FILE);

	if (args->key != NULL)
		args->keylen = strlen((char *)args->key);

	args->flag = flag;
	args->priority = priority;
out:
	return rc;
}

int get_jobID(int argc, const char *argv[])
{
	int job_id;

	if (argc == 2) {
		printf("Missing job ID after %s %s\n", argv[0], argv[1]);
		return -1;
	} else if (argc > 3) {
		printf("Too many operands.\n");
		return -1;
	}

	job_id = atoi(argv[2]);
	return job_id;
}

int main(int argc, const char *argv[])
{
	int rc = 0;
	int async_ops_driver;
	int iterator, i;

	if (argc < 2) {
		printf("Please mention operation after %s", argv[0]);
		rc = -1;
		exit(rc);
	}

	async_ops_driver = open("/proc/async_ops_driver", O_RDWR);

	if (async_ops_driver < 0) {
		printf("Cannot open the driver\n");
		rc = -1;
		goto out;
	}

	if (strcmp(DELETE_OP_STR, argv[1]) == 0) {
		int i;
		struct var_args args;
		rc = get_unlink_args(argc, argv, &args);

		if (rc < 0)
			goto out;

		rc = ioctl(async_ops_driver, IOCTL_DELETE, &args);

		for (i = 0; i < args.count; ++i) {
			if (args.filenames[i] != NULL) {
				free(args.filenames[i]);
			}
		}

	} else if (strcmp(CONCAT_OP_STR, argv[1]) == 0) {
		int i;
		struct concat_files args;
		rc = get_concatenate_args(argc, argv, &args);

		if (rc < 0)
			goto out;

		rc = ioctl(async_ops_driver, IOCTL_CONCATENATE, &args);

		for (i = 0; i < args.count; ++i) {
			if (args.input_file_paths[i] != NULL) {
				free(args.input_file_paths[i]);
			}
		}

		if (args.output_file_path != NULL) {
			free(args.output_file_path);
		}

	} else if (strcmp(RENAME_OP_STR, argv[1]) == 0) {
		int i;
		struct rename_files args;
		struct var_args vargs;
		rc = get_rename_args(argc, argv, &args, &vargs);

		if (rc < 0)
			goto out;

		rc = ioctl(async_ops_driver, IOCTL_RENAME, &args);

		for (i = 0; i < vargs.count; ++i) {
			if (vargs.filenames[i] != NULL) {
				free(vargs.filenames[i]);

				if (args.destination_file_paths[i] != NULL)
					free(args.destination_file_paths[i]);
			}
		}

	} else if (strcmp(STAT_OP_STR, argv[1]) == 0) {
		int i;
		struct rename_files args;
		struct var_args vargs;
		rc = get_rename_args(argc, argv, &args, &vargs);

		if (rc < 0)
			goto out;

		rc = ioctl(async_ops_driver, IOCTL_STAT, &args);

		for (i = 0; i < vargs.count; ++i) {
			if (vargs.filenames[i] != NULL) {
				free(vargs.filenames[i]);

				if (args.destination_file_paths[i] != NULL)
					free(args.destination_file_paths[i]);
			}
		}

	} else if (strcmp(LIST_JOBS_STR, argv[1]) == 0) {
		struct list_all_jobs args;
		char status[20];
		char operation[20];
		char priority[20];
		int uid = getuid();

		if (argc > 2) {
			printf("Too many arguments.\n");
			rc = -1;
			goto out;
		}

		rc = ioctl(async_ops_driver, IOCTL_GET_ACTIVE_JOBS, &args);
		if (rc < 0)
			goto out2;

		printf("JOB_ID\t\tOPERATION\tSTATUS\t\tPRIORITY\t\tTIMEonQ(s)\tUSER_ID\n");
		for (iterator = 0; iterator < args.count; ++iterator) {
			if (uid != ROOT_USER_ID &&
			    args.jobs[iterator].user_id != uid)
				continue;

			switch (args.jobs[iterator].job_status) {
			case PENDING:
				strcpy(status, "PENDING  ");
				break;
			case RUNNING:
				strcpy(status, "RUNNING  ");
				break;
			default:
				break;
			}

			switch (args.jobs[iterator].operation) {
			case DELETE_OP:
				strcpy(operation, "DELETE");
				break;
			case ENC_DEC_OP:
				strcpy(operation, "ENC_DEC");
				break;
			case CONCAT_OP:
				strcpy(operation, "CONCAT");
				break;
			case RENAME_OP:
				strcpy(operation, "RENAME");
				break;
			case COMP_DEC_OP:
				strcpy(operation, "COMP_DEC");
				break;
			case STAT_OP:
				strcpy(operation, "STAT");
				break;
			case HASH_OP:
				strcpy(operation, "HASH");
				break;
			default:
				break;
			}

			if (args.jobs[iterator].priority == PRIORITY_LOW) {
				strcpy(priority, "normal");
			} else if (args.jobs[iterator].priority ==
				   PRIORITY_HIGH) {
				strcpy(priority, "high");
			}

			printf("%-15d\t%-15s\t%-15s\t%-15s\t\t%-15d\t%-15d\n",
			       args.jobs[iterator].job_id, operation, status,
			       priority, (int)args.jobs[iterator].time_on_queue,
			       args.jobs[iterator].user_id);
		}

	} else if (strcmp(LIST_COMPLETED_JOBS, argv[1]) == 0) {
		struct list_completed_jobs args;
		int uid = getuid();
		if (argc != COMMAND_BASIC_ARGS) {
			printf("Usage: %s %s\n", argv[0], argv[1]);
			rc = -1;
			goto out;
		}

		rc = ioctl(async_ops_driver, IOCTL_GET_COMPLETED_JOBS, &args);
		if (rc < 0)
			goto out2;

		printf("List of completed jobs —\n");
		for (i = 0; i < args.count; i++) {
			if (uid != ROOT_USER_ID && args.jobs[i].user_id != uid)
				continue;
			printf("%d\n", args.jobs[i].job_id);
		}

	} else if (strcmp(POLL_STATUS, argv[1]) == 0) {
		int iterator;
		struct poll_status args;
		int uid = getuid();
		if (argc != COMMAND_BASIC_ARGS + 1) {
			printf("Usage: %s %s JOB_ID\n", argv[0], argv[1]);
			goto out;
		}
		args.job_id = atoi(argv[COMMAND_BASIC_ARGS]);

		rc = ioctl(async_ops_driver, IOCTL_GET_STATUS, &args);
		if (rc < 0)
			goto out2;

		if (uid != ROOT_USER_ID && args.user_id != uid) {
			printf("Operation not permitted\n");
			goto out;
		}

		if (args.job_status == PENDING) {
			printf("Job ID: %d — PENDING\n", args.job_id);
		} else if (args.job_status == RUNNING) {
			printf("Job ID: %d — RUNNING\n", args.job_id);
		} else if (args.job_status == COMPLETED) {
			if (args.count == 0) {
				printf("Job ID: %d — Completed\n", args.job_id);
				printf("Operation status: %d\n",
				       args.op_status);
			} else {
				printf("Job ID: %d — Completed\n", args.job_id);
				for (iterator = 0; iterator < args.count;
				     ++iterator) {
					printf("%s: %d\n",
					       args.filenames[iterator],
					       args.status[iterator]);
				}
			}
		}

	} else if (strcmp(PRIORITY_BOOST_STR, argv[1]) == 0) {
		int job_id;
		job_id = get_jobID(argc, argv);
		if (job_id <= 0)
			goto out;

		rc = ioctl(async_ops_driver, IOCTL_PRIORITY_BOOST, &job_id);
		if (rc < 0) {
			printf("Priority boost failed\n");
			goto out;
		}

	} else if (strcmp(DELETE_JOB_STR, argv[1]) == 0) {
		int job_id;
		job_id = get_jobID(argc, argv);
		if (job_id <= 0) {
			goto out;
		}
		rc = ioctl(async_ops_driver, IOCTL_DELETE_JOB, job_id);

	} else if (strcmp(ENC_DEC_STR, argv[1]) == 0) {
		struct enc_dec_args enc_dec_args;
		optind = 2;
		rc = get_enc_dec_args(argc, argv, &enc_dec_args);
		if (rc < 0)
			goto out;
		rc = ioctl(async_ops_driver, IOCTL_ENC_DEC, &enc_dec_args);

		if (enc_dec_args.input_file_path != NULL)
			free(enc_dec_args.input_file_path);

		if (enc_dec_args.output_file_path != NULL)
			free(enc_dec_args.output_file_path);

	} else if (strcmp(COMP_DEC_STR, argv[1]) == 0) {
		struct compress_args compress_args;
		optind = 2;
		rc = get_comp_args(argc, argv, &compress_args);
		if (rc < 0)
			goto out;
		rc = ioctl(async_ops_driver, IOCTL_COMP_DEC, &compress_args);

		if (compress_args.input_file_path != NULL)
			free(compress_args.input_file_path);

		if (compress_args.output_file_path != NULL)
			free(compress_args.output_file_path);

	} else if (strcmp(HASH_OP_STR, argv[1]) == 0) {
		struct hash_args hash_args;
		rc = get_hash_args(argc, argv, &hash_args);
		if (rc < 0)
			goto out;
		rc = ioctl(async_ops_driver, IOCTL_HASH, &hash_args);

		if (hash_args.input_file_path != NULL)
			free(hash_args.input_file_path);

		if (hash_args.output_file_path != NULL)
			free(hash_args.output_file_path);

	} else {
		printf("Invalid operation\n");
	}

out2:

	if (rc < 0) {
		perror("Error:");
	} else if (rc > 0) {
		printf("Id of submitted job:%d\n", rc);
	}

out:
	close(async_ops_driver);
	exit(rc);
}
