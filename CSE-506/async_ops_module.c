#include "async_ops_module.h"
// #include "utils.h"

static struct proc_dir_entry *async_ops_proc_entry;

static struct workqueue_struct *async_ops_wq, *hp_async_ops_wq, *cleanup_queue;
static int global_job_identifier;

static char *pwd, *pwd_full_path;

// initialising the linked list
LIST_HEAD(active_jobs);
LIST_HEAD(completed_jobs);

int completed_jobs_count = 0;
static int job_list_swapper(void);
static void job_list_swapper_timer_thread(struct work_struct *);
static DECLARE_DELAYED_WORK(job_for_cleanup_queue,
			    job_list_swapper_timer_thread);

//Mutex for active and completed jobs list
struct mutex active_list_mutex;
struct mutex completed_list_mutex;

unsigned int isJobComplete(struct work_struct *work)
{
	unsigned int ret = 0;
	if (!work_pending(work)) {
		if (!work_busy(work)) {
			ret = 1;
		}
	}
	return ret;
}

unsigned int operation_of_multiple_file_type(int op)
{
	unsigned int ret = 0;
	if (op == RENAME_OP || op == STAT_OP || op == DELETE_OP) {
		ret = 1;
	}
	return ret;
}

static void tmp_list_completed_jobs(void)
{
	struct completed_jobs_node *itr;
	mutex_lock(&completed_list_mutex);
	printk("Listing completed jobs(Job_id) for correctness\n");
	list_for_each_entry (itr, &completed_jobs, list) {
		printk("%d\n", itr->job_id);
	}
	mutex_unlock(&completed_list_mutex);
	return;
}

//Function only called by the timer work_struct in the cleanup queue
static void job_list_swapper_timer_thread(struct work_struct *unused)
{
	job_list_swapper();
	queue_delayed_work(cleanup_queue, &job_for_cleanup_queue,
			   msecs_to_jiffies(10000));
	return;
}

//Function used to lazily move COMPLETED jobs from active list to completed list. Also, write job's result values to a file
static int job_list_swapper(void)
{
	int err = 0;
	int iterator = 0;
	int j;
	int free_completed_node = 0, free_completed_node_args = 0,
	    free_wrapper_node = 0;
	char *buf = NULL;
	char str[STR_BUFFER_FOR_JOB_ID];
	char *user_pass_path = NULL;
	struct file *fp = NULL;
	struct work_struct_wrapper *itr, *tmp;
	struct completed_jobs_node *to_insert_completed_job = NULL,
				   *first_node = NULL;
	struct var_args *itr_args;
	mutex_lock(&active_list_mutex);
	mutex_lock(&completed_list_mutex);

	list_for_each_entry_safe (itr, tmp, &active_jobs, list) {
		if (itr->job_status == COMPLETED ||
		    isJobComplete(&itr->async_job)) {
			to_insert_completed_job = kmalloc(
				sizeof(struct completed_jobs_node), GFP_KERNEL);
			if (!to_insert_completed_job) {
				pr_err("Could not allocate to_insert_completed_job\n");
				err = -ENOMEM;
				free_wrapper_node = 1;
				goto out;
			}

			if (user_pass_path == NULL) {
				user_pass_path = kmalloc(PATH_MAX, GFP_KERNEL);
				if (!user_pass_path) {
					pr_err("Could not allocate user_pass_path\n");
					err = -ENOMEM;
					free_completed_node = 1;
					free_wrapper_node = 1;
					goto out;
				}
			}
			memset(user_pass_path, 0, PATH_MAX);

			if (buf == NULL) {
				buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
				if (!buf) {
					pr_err("Could not allocate buf\n");
					err = -ENOMEM;
					free_completed_node = 1;
					free_wrapper_node = 1;
					goto out;
				}
			}
			memset(buf, 0, PAGE_SIZE);

			memset(str, 0, STR_BUFFER_FOR_JOB_ID);
			sprintf(str, "%d", itr->job_id);
			strcat(user_pass_path, pwd_full_path);
			strcat(user_pass_path, "/");
			strcat(user_pass_path, str);
			strcat(user_pass_path, DOT_OUT_FILE);

			j = 0;
			fp = filp_open(user_pass_path,
				       O_WRONLY | O_CREAT | O_TRUNC, 0777);
			if (fp == NULL || IS_ERR(fp)) {
				printk("%ld\n", PTR_ERR(fp));
				err = -EIO;
				pr_err("Output file failed to open\n");
				free_completed_node = 1;
				free_wrapper_node = 1;
				goto out;
			}
			fp->f_pos = 0;
			j += sprintf(buf + j, "Job ID: %d — Completed\n",
				     itr->job_id);

			if (operation_of_multiple_file_type(itr->operation)) {
				to_insert_completed_job->args = kmalloc(
					sizeof(struct var_args), GFP_KERNEL);
				if (itr->operation == DELETE_OP) {
					itr_args = (struct var_args *)itr->args;
				} else {
					itr_args = ((struct rename_files *)
							    itr->args)
							   ->vargs;
				}

				to_insert_completed_job->args->count =
					itr_args->count;
				for (iterator = 0; iterator < itr_args->count;
				     ++iterator) {
					to_insert_completed_job->args
						->filenames[iterator] =
						kmalloc(PATH_MAX, GFP_KERNEL);
					strcpy(to_insert_completed_job->args
						       ->filenames[iterator],
					       itr_args->filenames[iterator]);
					to_insert_completed_job
						->status[iterator] =
						itr->status[iterator];

					j += sprintf(
						buf + j, "%s : %d\n",
						to_insert_completed_job->args
							->filenames[iterator],
						to_insert_completed_job
							->status[iterator]);
				}
			} else {
				to_insert_completed_job->op_status =
					itr->op_status;
				j += sprintf(
					buf + j, "Operation status: %d\n",
					to_insert_completed_job->op_status);
			}

			err = sys_crypto_write_file(fp, buf, j);
			if (err < 0) {
				pr_err("Status output file write error\n");
				err = -EIO;
				free_completed_node_args = 1;
				free_completed_node = 1;
				free_wrapper_node = 1;
				goto out;
			}

			if (fp) {
				if (!IS_ERR(fp)) {
					filp_close(fp, NULL);
					fp = NULL;
				}
			}

			to_insert_completed_job->user_id = itr->user_id;
			to_insert_completed_job->job_id = itr->job_id;
			to_insert_completed_job->op = itr->operation;

			INIT_LIST_HEAD(&to_insert_completed_job->list);
			list_add_tail(&to_insert_completed_job->list,
				      &completed_jobs);

			if (completed_jobs_count == MAX_COMPLETED_JOBS_COUNT) {
				first_node = list_first_entry(
					&completed_jobs,
					struct completed_jobs_node, list);
				if (first_node) {
					list_del(&first_node->list);
					if (operation_of_multiple_file_type(
						    first_node->op)) {
						var_arg_cleanup(
							first_node->args);
					}
					kfree(first_node);
				}
			} else {
				completed_jobs_count = completed_jobs_count + 1;
			}

			list_del(&itr->list);
			if (operation_of_multiple_file_type(itr->operation)) {
				if (itr->operation == DELETE_OP) {
					var_arg_cleanup(itr->args);
				} else {
					rename_op_cleanup(itr->args);
				}
			}
			kfree(itr);
		}
	}

out:
	mutex_unlock(&completed_list_mutex);
	mutex_unlock(&active_list_mutex);
	if (buf) {
		kfree(buf);
	}
	if (user_pass_path) {
		kfree(user_pass_path);
	}
	if (free_completed_node) {
		if (free_completed_node_args) {
			var_arg_cleanup(to_insert_completed_job->args);
		}
		kfree(to_insert_completed_job);
	}
	if (free_wrapper_node) {
		list_del(&itr->list);
		if (operation_of_multiple_file_type(itr->operation)) {
			if (itr->operation == DELETE_OP) {
				var_arg_cleanup(itr->args);
			} else {
				rename_op_cleanup(itr->args);
			}
		}
		kfree(itr);
	}
	if (fp) {
		if (!IS_ERR(fp)) {
			filp_close(fp, NULL);
		}
	}
	return err;
}

//Function used to get status of a job from the active_list using job_id
static int populate_status_from_active_list(struct poll_status *ret)
{
	int err = -EINVAL;
	int job_id = ret->job_id;
	struct work_struct_wrapper *itr;
	mutex_lock(&active_list_mutex);
	list_for_each_entry (itr, &active_jobs, list) {
		if (itr->job_id == job_id) {
			if (work_pending(&itr->async_job)) {
				ret->job_status = PENDING;
			} else {
				ret->job_status = RUNNING;
			}
			ret->op = itr->operation;
			ret->user_id = itr->user_id;
			err = 0;
			goto out;
		}
	}
out:
	mutex_unlock(&active_list_mutex);
	return err;
}

//Function used to get_status of a job from the completed_list using job_id
static int populate_status_from_completed_list(struct poll_status *ret)
{
	int err = -EINVAL;
	int i = 0;
	int job_id = ret->job_id;
	struct completed_jobs_node *itr;
	mutex_lock(&completed_list_mutex);
	list_for_each_entry (itr, &completed_jobs, list) {
		if (itr->job_id == job_id) {
			ret->job_status = COMPLETED;
			ret->op = itr->op;
			ret->user_id = itr->user_id;
			//If operation is RENAME, STAT or DELETE
			if (operation_of_multiple_file_type(itr->op)) {
				ret->count = itr->args->count;
				for (i = 0; i < itr->args->count; i++) {
					ret->status[i] = itr->status[i];
					strcpy(ret->filenames[i],
					       itr->args->filenames[i]);
				}
			}
			//For operations other than RENAME, STAT or DELETE
			else {
				ret->count = 0;
				ret->op_status = itr->op_status;
			}
			err = 0;
			goto out;
		}
	}
out:
	mutex_unlock(&completed_list_mutex);
	return err;
}

//Add a new job, checks if enough jobs are already present in the WQ
static int add_job(struct list_head *new, struct list_head *head)
{
	struct work_struct_wrapper *job_wrapper_iterator, *new_job_wrapper;
	int count = 0;

	new_job_wrapper = container_of(new, struct work_struct_wrapper, list);
	mutex_lock(&active_list_mutex);

	list_for_each_entry (job_wrapper_iterator, &active_jobs, list) {
		if (work_pending(&job_wrapper_iterator->async_job) ||
		    work_busy(&job_wrapper_iterator->async_job)) {
			count++;
			if (count >= MAX_ACTIVE_JOBS) {
				mutex_unlock(&active_list_mutex);
				return -1;
			}
		}
	}

	list_add_tail(new, head);
	getnstimeofday(&new_job_wrapper->time_of_queueing);
	mutex_unlock(&active_list_mutex);
	return 0;
}

//Function used to delete a job from WQ only if it's in pending state, also deletes its entry from our active list
static int delete_job(int job_id)
{
	struct work_struct_wrapper *job_wrapper, *temp;
	int rc = 0;
	int uid = current_cred()->uid.val;

	mutex_lock(&active_list_mutex);
	list_for_each_entry_safe (job_wrapper, temp, &active_jobs, list) {
		if (job_wrapper->job_id == job_id) {
			if (job_wrapper->user_id != uid) {
				rc = -EPERM;
				goto out;
			}
			if (work_pending(&job_wrapper->async_job) &&
			    cancel_work_sync(&job_wrapper->async_job)) {
				list_del(&job_wrapper->list);
				if (job_wrapper->operation == DELETE_OP) {
					var_arg_cleanup(job_wrapper->args);

				} else if (job_wrapper->operation ==
					   ENC_DEC_OP) {
					enc_dec_op_cleanup(job_wrapper->args);

				} else if (job_wrapper->operation ==
						   RENAME_OP ||
					   job_wrapper->operation == STAT_OP) {
					rename_op_cleanup(job_wrapper->args);

				} else if (job_wrapper->operation ==
					   CONCAT_OP) {
					concat_op_cleanup(job_wrapper->args);

				} else if (job_wrapper->operation ==
					   COMP_DEC_OP) {
					comp_dec_op_cleanup(job_wrapper->args);
				} else if (job_wrapper->operation == HASH_OP) {
					hash_op_cleanup(job_wrapper->args);
				}

				kfree(job_wrapper);
				// similarly do for all operations
				printk("Job ID found and pending\n");
				goto out;
			}

			printk("This job is currently running/completed\n");
			rc = -EPERM;
			goto out;
		}
	}
	printk("JOB ID NOT FOUND\n");
	rc = -EINVAL;

out:
	mutex_unlock(&active_list_mutex);
	return rc;
}

//Function used to populate jobs from the completed list
static void populate_completed_jobs(struct list_completed_jobs *ret)
{
	int i = 0;
	struct completed_jobs_node *itr;
	mutex_lock(&completed_list_mutex);
	list_for_each_entry (itr, &completed_jobs, list) {
		ret->jobs[i].user_id = itr->user_id;
		ret->jobs[i].job_id = itr->job_id;
		ret->jobs[i].operation = itr->op;
		i = i + 1;
	}
	ret->count = i;
	mutex_unlock(&completed_list_mutex);
	return;
}

//Function used to list all active jobs
static void list_jobs_status(struct list_all_jobs *args)
{
	struct work_struct_wrapper *job_wrapper;
	int count = 0, pending;
	struct timespec tmptime;

	mutex_lock(&active_list_mutex);

	list_for_each_entry (job_wrapper, &active_jobs, list) {
		if ((pending = work_pending(&job_wrapper->async_job)) ||
		    work_busy(&job_wrapper->async_job)) {
			args->jobs[count].user_id = job_wrapper->user_id;
			args->jobs[count].job_id = job_wrapper->job_id;
			if (pending) {
				args->jobs[count].job_status = PENDING;
			} else {
				args->jobs[count].job_status = RUNNING;
			}
			args->jobs[count].priority = job_wrapper->priority;
			getnstimeofday(&tmptime);
			args->jobs[count].time_on_queue =
				tmptime.tv_sec -
				job_wrapper->time_of_queueing.tv_sec;
			args->jobs[count].operation = job_wrapper->operation;
			count++;
		}
	}

	// Debug: for completed list correctness, checking active_jobs count
	// printk("Count of active jobs: %d\n", count);

	args->count = count;
	mutex_unlock(&active_list_mutex);
	return;
}

//Boost priority of a job if it is in pending state and given its current priority is LOW
static int boost_job_priority(int job_id)
{
	struct work_struct_wrapper *job_wrapper_iterator;
	int err = 0;
	int uid = current_cred()->uid.val;
	mutex_lock(&active_list_mutex);

	list_for_each_entry (job_wrapper_iterator, &active_jobs, list) {
		if (job_wrapper_iterator->job_id == job_id) {
			printk("boost_start\n");
			if (uid != ROOT_USER_ID &&
			    job_wrapper_iterator->user_id != uid)
				break;
			if (work_pending(&job_wrapper_iterator->async_job) &&
			    job_wrapper_iterator->priority == PRIORITY_LOW &&
			    cancel_work_sync(
				    &job_wrapper_iterator->async_job)) {
				job_wrapper_iterator->priority = PRIORITY_HIGH;
				queue_work(hp_async_ops_wq,
					   &job_wrapper_iterator->async_job);
				printk("a\n");
				goto out;
			} else {
				err = -EPERM;
				printk("b\n");
				goto out;
			}
		}
	}
	err = -EPERM;
out:
	mutex_unlock(&active_list_mutex);
	return err;
}

//Primary ioctl handler, Handles Kernel WQ API calls and operation ioctls
static long async_ops_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	long err = 0;
	int iterator;
	char *filename_str, *temp_str = NULL;
	struct filename *temp_filename;
	struct var_args *args;
	struct concat_files *concat_args;
	struct rename_files *rename_args;
	struct var_args *vargs;
	struct list_all_jobs *list_jobs_args;
	struct list_completed_jobs *list_completed_jobs;
	struct work_struct_wrapper *async_job_wrapper = NULL;
	struct enc_dec_args *enc_dec_args;
	struct poll_status *poll_status_ret = NULL;
	struct hash_args *hash_args;
	struct compress_args *compress_args;
	int job_id;

	async_job_wrapper =
		kmalloc(sizeof(struct work_struct_wrapper), GFP_KERNEL);
	if (!async_job_wrapper) {
		err = -ENOMEM;
		goto out;
	}

	switch (cmd) {
	case IOCTL_DELETE:
		async_job_wrapper->args =
			kmalloc(sizeof(struct var_args), GFP_KERNEL);
		if (!async_job_wrapper->args) {
			kfree(async_job_wrapper);
			err = -ENOMEM;
			goto out;
		}

		async_job_wrapper->job_id = ++global_job_identifier;
		async_job_wrapper->user_id = current_cred()->uid.val;
		async_job_wrapper->job_status = PENDING;
		async_job_wrapper->operation = DELETE_OP;

		if (copy_from_user(async_job_wrapper->args, (void *)arg,
				   sizeof(struct var_args))) {
			kfree(async_job_wrapper->args);
			kfree(async_job_wrapper);
			return -EFAULT;
		}

		args = (struct var_args *)async_job_wrapper->args;

		for (iterator = 0; iterator < args->count; ++iterator) {
			filename_str = kmalloc(PATH_MAX, GFP_KERNEL);
			temp_filename = getname(args->filenames[iterator]);
			strcpy(filename_str, temp_filename->name);
			// printk("Input file is %s", filename_str);
			putname(temp_filename);
			args->filenames[iterator] = filename_str;
		}

		async_job_wrapper->priority = args->priority;

		// adding jobs to the list
		INIT_LIST_HEAD(&async_job_wrapper->list);
		err = add_job(&async_job_wrapper->list, &active_jobs);

		if (err < 0) {
			printk("Could not add job to the queue");
			var_arg_cleanup(args);
			kfree(async_job_wrapper);
			return -ENOMEM;
		}

		INIT_WORK(&async_job_wrapper->async_job, delete_func);
		if (async_job_wrapper->priority == PRIORITY_LOW) {
			queue_work(async_ops_wq, &async_job_wrapper->async_job);
		} else if (async_job_wrapper->priority == PRIORITY_HIGH) {
			queue_work(hp_async_ops_wq,
				   &async_job_wrapper->async_job);
		}

		return global_job_identifier;
		break;

	case IOCTL_GET_ACTIVE_JOBS:
		job_list_swapper();
		tmp_list_completed_jobs();
		list_jobs_args =
			kmalloc(sizeof(struct list_all_jobs), GFP_KERNEL);
		if (!list_jobs_args)
			return -ENOMEM;

		list_jobs_status(list_jobs_args);
		if (copy_to_user((struct list_all_jobs *)arg, list_jobs_args,
				 sizeof(struct list_all_jobs))) {
			err = -EFAULT;
		}
		kfree(list_jobs_args);
		break;

	case IOCTL_GET_COMPLETED_JOBS:
		job_list_swapper();
		list_completed_jobs =
			kmalloc(sizeof(struct list_completed_jobs), GFP_KERNEL);
		if (!list_completed_jobs)
			return -ENOMEM;

		populate_completed_jobs(list_completed_jobs);
		if (copy_to_user((struct list_completed_jobs *)arg,
				 list_completed_jobs,
				 sizeof(struct list_completed_jobs))) {
			err = -EFAULT;
		}
		kfree(list_completed_jobs);
		break;

	case IOCTL_GET_STATUS:
		poll_status_ret =
			kmalloc(sizeof(struct poll_status), GFP_KERNEL);
		if (!poll_status_ret)
			return -ENOMEM;

		if (copy_from_user(poll_status_ret, (struct poll_status *)arg,
				   sizeof(struct poll_status))) {
			kfree(poll_status_ret);
			err = -EFAULT;
			break;
		}
		job_list_swapper();
		err = populate_status_from_completed_list(poll_status_ret);
		if (err < 0) {
			err = populate_status_from_active_list(poll_status_ret);
		}
		if (err == 0) {
			if (copy_to_user((struct poll_status *)arg,
					 poll_status_ret,
					 sizeof(struct poll_status))) {
				err = -EFAULT;
			}
		}

		kfree(poll_status_ret);
		break;

	case IOCTL_PRIORITY_BOOST:
		if (copy_from_user(&job_id, (int *)arg, sizeof(int))) {
			return -EFAULT;
		}
		err = boost_job_priority(job_id);
		break;

	case IOCTL_DELETE_JOB:
		err = delete_job(arg);
		break;

	case IOCTL_ENC_DEC:
		async_job_wrapper->args =
			kmalloc(sizeof(struct enc_dec_args), GFP_KERNEL);
		if (!async_job_wrapper->args) {
			kfree(async_job_wrapper);
			err = -ENOMEM;
			goto out;
		}

		async_job_wrapper->job_id = ++global_job_identifier;
		async_job_wrapper->user_id = current_cred()->uid.val;
		async_job_wrapper->job_status = PENDING;
		async_job_wrapper->operation = ENC_DEC_OP;

		if (copy_from_user(async_job_wrapper->args, (void *)arg,
				   sizeof(struct enc_dec_args))) {
			kfree(async_job_wrapper->args);
			kfree(async_job_wrapper);
			return -EFAULT;
		}

		enc_dec_args = (struct enc_dec_args *)async_job_wrapper->args;

		temp_str = kmalloc((enc_dec_args->keylen + 1) * (sizeof(char)),
				   GFP_KERNEL);
		if (strncpy_from_user(temp_str, enc_dec_args->key,
				      enc_dec_args->keylen + 1) < 0) {
			kfree(temp_str);
			kfree(async_job_wrapper->args);
			kfree(async_job_wrapper);
			return -EFAULT;
		}
		enc_dec_args->key = temp_str;

		filename_str = kmalloc(PATH_MAX, GFP_KERNEL);
		temp_filename = getname(enc_dec_args->input_file_path);
		strcpy(filename_str, temp_filename->name);
		putname(temp_filename);
		enc_dec_args->input_file_path = filename_str;

		filename_str = kmalloc(PATH_MAX, GFP_KERNEL);
		temp_filename = getname(enc_dec_args->output_file_path);
		strcpy(filename_str, temp_filename->name);
		putname(temp_filename);
		enc_dec_args->output_file_path = filename_str;

		async_job_wrapper->priority = enc_dec_args->priority;
		INIT_LIST_HEAD(&async_job_wrapper->list);
		err = add_job(&async_job_wrapper->list, &active_jobs);

		if (err < 0) {
			printk("Could not add job to the queue");
			enc_dec_op_cleanup(enc_dec_args);
			kfree(async_job_wrapper);
			return -ENOMEM;
		}

		INIT_WORK(&async_job_wrapper->async_job, cryptocopy);
		if (async_job_wrapper->priority == PRIORITY_LOW) {
			queue_work(async_ops_wq, &async_job_wrapper->async_job);
		} else if (async_job_wrapper->priority == PRIORITY_HIGH) {
			queue_work(hp_async_ops_wq,
				   &async_job_wrapper->async_job);
		}
		return global_job_identifier;
		break;

	case IOCTL_COMP_DEC:
		async_job_wrapper->args =
			kmalloc(sizeof(struct compress_args), GFP_KERNEL);
		if (!async_job_wrapper->args) {
			kfree(async_job_wrapper);
			err = -ENOMEM;
			goto out;
		}

		async_job_wrapper->job_id = ++global_job_identifier;
		async_job_wrapper->user_id = current_cred()->uid.val;
		async_job_wrapper->job_status = PENDING;
		async_job_wrapper->operation = COMP_DEC_OP;

		if (copy_from_user(async_job_wrapper->args, (void *)arg,
				   sizeof(struct compress_args))) {
			kfree(async_job_wrapper->args);
			kfree(async_job_wrapper);
			return -EFAULT;
		}

		compress_args = (struct compress_args *)async_job_wrapper->args;

		filename_str = kmalloc(PATH_MAX, GFP_KERNEL);
		temp_filename = getname(compress_args->input_file_path);
		strcpy(filename_str, temp_filename->name);
		putname(temp_filename);
		compress_args->input_file_path = filename_str;

		filename_str = kmalloc(PATH_MAX, GFP_KERNEL);
		temp_filename = getname(compress_args->output_file_path);
		strcpy(filename_str, temp_filename->name);
		putname(temp_filename);
		compress_args->output_file_path = filename_str;

		async_job_wrapper->priority = compress_args->priority;

		INIT_LIST_HEAD(&async_job_wrapper->list);
		err = add_job(&async_job_wrapper->list, &active_jobs);

		if (err < 0) {
			printk("Could not add job to the queue");
			comp_dec_op_cleanup(compress_args);
			kfree(async_job_wrapper);
			return -ENOMEM;
		}

		INIT_WORK(&async_job_wrapper->async_job, compcopy);
		if (async_job_wrapper->priority == PRIORITY_LOW) {
			queue_work(async_ops_wq, &async_job_wrapper->async_job);
		} else if (async_job_wrapper->priority == PRIORITY_HIGH) {
			queue_work(hp_async_ops_wq,
				   &async_job_wrapper->async_job);
		}
		return global_job_identifier;
		break;

	case IOCTL_HASH:
		async_job_wrapper->args =
			kmalloc(sizeof(struct hash_args), GFP_KERNEL);
		if (!async_job_wrapper->args) {
			kfree(async_job_wrapper);
			err = -ENOMEM;
			goto out;
		}

		async_job_wrapper->job_id = ++global_job_identifier;
		async_job_wrapper->user_id = current_cred()->uid.val;
		async_job_wrapper->job_status = PENDING;
		async_job_wrapper->operation = HASH_OP;

		if (copy_from_user(async_job_wrapper->args, (void *)arg,
				   sizeof(struct hash_args))) {
			kfree(async_job_wrapper->args);
			kfree(async_job_wrapper);
			return -EFAULT;
		}

		hash_args = (struct hash_args *)async_job_wrapper->args;

		filename_str = kmalloc(PATH_MAX, GFP_KERNEL);
		temp_filename = getname(hash_args->input_file_path);
		strcpy(filename_str, temp_filename->name);
		putname(temp_filename);
		hash_args->input_file_path = filename_str;

		filename_str = kmalloc(PATH_MAX, GFP_KERNEL);
		temp_filename = getname(hash_args->output_file_path);
		strcpy(filename_str, temp_filename->name);
		putname(temp_filename);
		hash_args->output_file_path = filename_str;

		async_job_wrapper->priority = hash_args->priority;

		INIT_LIST_HEAD(&async_job_wrapper->list);
		err = add_job(&async_job_wrapper->list, &active_jobs);

		if (err < 0) {
			printk("Could not add job to the queue");
			hash_op_cleanup(hash_args);
			kfree(async_job_wrapper);
			return -ENOMEM;
		}

		INIT_WORK(&async_job_wrapper->async_job, compute_file_hash);
		if (async_job_wrapper->priority == PRIORITY_LOW) {
			queue_work(async_ops_wq, &async_job_wrapper->async_job);
		} else if (async_job_wrapper->priority == PRIORITY_HIGH) {
			queue_work(hp_async_ops_wq,
				   &async_job_wrapper->async_job);
		}
		return global_job_identifier;
		break;

	case IOCTL_CONCATENATE:
		async_job_wrapper->args =
			kmalloc(sizeof(struct concat_files), GFP_KERNEL);
		if (!async_job_wrapper->args) {
			kfree(async_job_wrapper);
			err = -ENOMEM;
			goto out;
		}

		async_job_wrapper->job_id = ++global_job_identifier;
		async_job_wrapper->user_id = current_cred()->uid.val;
		async_job_wrapper->job_status = PENDING;
		async_job_wrapper->operation = CONCAT_OP;

		if (copy_from_user(async_job_wrapper->args, (void *)arg,
				   sizeof(struct concat_files))) {
			kfree(async_job_wrapper->args);
			kfree(async_job_wrapper);
			return -EFAULT;
		}

		concat_args = (struct concat_files *)async_job_wrapper->args;

		for (iterator = 0; iterator < concat_args->count; ++iterator) {
			filename_str = kmalloc(PATH_MAX, GFP_KERNEL);
			temp_filename = getname(
				concat_args->input_file_paths[iterator]);
			strcpy(filename_str, temp_filename->name);
			putname(temp_filename);
			concat_args->input_file_paths[iterator] = filename_str;
		}

		filename_str = kmalloc(PATH_MAX, GFP_KERNEL);
		temp_filename = getname(concat_args->output_file_path);
		strcpy(filename_str, temp_filename->name);
		putname(temp_filename);
		concat_args->output_file_path = filename_str;

		async_job_wrapper->priority = concat_args->priority;

		INIT_LIST_HEAD(&async_job_wrapper->list);
		err = add_job(&async_job_wrapper->list, &active_jobs);

		if (err < 0) {
			printk("Could not add job to the queue");
			concat_op_cleanup(concat_args);
			kfree(async_job_wrapper);
			return -ENOMEM;
		}

		INIT_WORK(&async_job_wrapper->async_job, concatenate_func);
		if (async_job_wrapper->priority == PRIORITY_LOW) {
			queue_work(async_ops_wq, &async_job_wrapper->async_job);
		} else if (async_job_wrapper->priority == PRIORITY_HIGH) {
			queue_work(hp_async_ops_wq,
				   &async_job_wrapper->async_job);
		}

		return global_job_identifier;
		break;

	case IOCTL_RENAME:
		async_job_wrapper->args =
			kmalloc(sizeof(struct rename_files), GFP_KERNEL);
		if (!async_job_wrapper->args) {
			kfree(async_job_wrapper);
			err = -ENOMEM;
			goto out;
		}

		async_job_wrapper->job_id = ++global_job_identifier;
		async_job_wrapper->user_id = current_cred()->uid.val;
		async_job_wrapper->job_status = PENDING;
		async_job_wrapper->operation = RENAME_OP;

		if (copy_from_user(async_job_wrapper->args, (void *)arg,
				   sizeof(struct rename_files))) {
			kfree(async_job_wrapper->args);
			kfree(async_job_wrapper);
			return -EFAULT;
		}

		rename_args = (struct rename_files *)async_job_wrapper->args;

		vargs = kmalloc(sizeof(struct var_args), GFP_KERNEL);
		if (!vargs) {
			kfree(rename_args);
			kfree(async_job_wrapper);
			err = -ENOMEM;
			goto out;
		}

		if (copy_from_user(vargs, rename_args->vargs,
				   sizeof(struct var_args))) {
			kfree(vargs);
			kfree(rename_args);
			kfree(async_job_wrapper);
			return -EFAULT;
		}

		rename_args->vargs = vargs;

		for (iterator = 0; iterator < rename_args->vargs->count;
		     ++iterator) {
			filename_str = kmalloc(PATH_MAX, GFP_KERNEL);
			temp_filename = getname(
				rename_args->vargs->filenames[iterator]);
			strcpy(filename_str, temp_filename->name);
			putname(temp_filename);
			rename_args->vargs->filenames[iterator] = filename_str;
		}

		for (iterator = 0; iterator < rename_args->vargs->count;
		     ++iterator) {
			filename_str = kmalloc(PATH_MAX, GFP_KERNEL);
			temp_filename = getname(
				rename_args->destination_file_paths[iterator]);
			strcpy(filename_str, temp_filename->name);
			putname(temp_filename);
			rename_args->destination_file_paths[iterator] =
				filename_str;
		}

		async_job_wrapper->priority = rename_args->vargs->priority;

		INIT_LIST_HEAD(&async_job_wrapper->list);
		err = add_job(&async_job_wrapper->list, &active_jobs);

		if (err < 0) {
			printk("Could not add job to the queue");
			rename_op_cleanup(rename_args);
			kfree(async_job_wrapper);
			return -ENOMEM;
		}

		INIT_WORK(&async_job_wrapper->async_job, rename_func);
		if (async_job_wrapper->priority == PRIORITY_LOW) {
			queue_work(async_ops_wq, &async_job_wrapper->async_job);
		} else if (async_job_wrapper->priority == PRIORITY_HIGH) {
			queue_work(hp_async_ops_wq,
				   &async_job_wrapper->async_job);
		}

		return global_job_identifier;
		break;

	case IOCTL_STAT:
		async_job_wrapper->args =
			kmalloc(sizeof(struct rename_files), GFP_KERNEL);
		if (!async_job_wrapper->args) {
			kfree(async_job_wrapper);
			err = -ENOMEM;
			goto out;
		}

		async_job_wrapper->job_id = ++global_job_identifier;
		async_job_wrapper->user_id = current_cred()->uid.val;
		async_job_wrapper->job_status = PENDING;
		async_job_wrapper->operation = STAT_OP;

		if (copy_from_user(async_job_wrapper->args, (void *)arg,
				   sizeof(struct rename_files))) {
			kfree(async_job_wrapper->args);
			kfree(async_job_wrapper);
			return -EFAULT;
		}

		rename_args = (struct rename_files *)async_job_wrapper->args;

		vargs = kmalloc(sizeof(struct var_args), GFP_KERNEL);
		if (!vargs) {
			kfree(rename_args);
			kfree(async_job_wrapper);
			err = -ENOMEM;
			goto out;
		}

		if (copy_from_user(vargs, rename_args->vargs,
				   sizeof(struct var_args))) {
			kfree(vargs);
			kfree(rename_args);
			kfree(async_job_wrapper);
			return -EFAULT;
		}

		rename_args->vargs = vargs;

		for (iterator = 0; iterator < rename_args->vargs->count;
		     ++iterator) {
			filename_str = kmalloc(PATH_MAX, GFP_KERNEL);
			temp_filename = getname(
				rename_args->vargs->filenames[iterator]);
			strcpy(filename_str, temp_filename->name);
			putname(temp_filename);
			rename_args->vargs->filenames[iterator] = filename_str;
		}

		for (iterator = 0; iterator < rename_args->vargs->count;
		     ++iterator) {
			filename_str = kmalloc(PATH_MAX, GFP_KERNEL);
			temp_filename = getname(
				rename_args->destination_file_paths[iterator]);
			strcpy(filename_str, temp_filename->name);
			putname(temp_filename);
			rename_args->destination_file_paths[iterator] =
				filename_str;
		}

		async_job_wrapper->priority = rename_args->vargs->priority;

		INIT_LIST_HEAD(&async_job_wrapper->list);
		err = add_job(&async_job_wrapper->list, &active_jobs);

		if (err < 0) {
			printk("Could not add job to the queue");
			rename_op_cleanup(rename_args);
			kfree(async_job_wrapper);
			return -ENOMEM;
		}

		INIT_WORK(&async_job_wrapper->async_job, stat_func);
		if (async_job_wrapper->priority == PRIORITY_LOW) {
			queue_work(async_ops_wq, &async_job_wrapper->async_job);
		} else if (async_job_wrapper->priority == PRIORITY_HIGH) {
			queue_work(hp_async_ops_wq,
				   &async_job_wrapper->async_job);
		}

		return global_job_identifier;
		break;

	default:
		err = -EINVAL;
	}
out:
	return err;
}

static struct file_operations file_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = async_ops_ioctl,
};

//Module intialiser, initialises all the WQs and locks. Also intiate the timer function.
static int __init init_async_ops(void)
{
	struct path pwd_path;
	mutex_init(&active_list_mutex);
	mutex_init(&completed_list_mutex);

	pwd = kmalloc(PATH_MAX, GFP_KERNEL);
	get_fs_pwd(current->fs, &pwd_path);
	pwd_full_path = dentry_path_raw(pwd_path.dentry, pwd, PATH_MAX);
	printk("PWD: %s", pwd_full_path);

	async_ops_proc_entry =
		proc_create("async_ops_driver", 0666, NULL, &file_ops);
	async_ops_wq = create_workqueue("async_ops");
	hp_async_ops_wq = alloc_workqueue(
		"hp_async_ops", WQ_HIGHPRI | WQ_MEM_RECLAIM | __WQ_LEGACY, 1);
	cleanup_queue = create_singlethread_workqueue("cleanup_scheduler");

	queue_delayed_work(cleanup_queue, &job_for_cleanup_queue,
			   msecs_to_jiffies(10000));

	path_put(&pwd_path);
	printk("Installed async_ops_module\n");
	return 0;
}

//Cleanup of WQs and completed_list during module exit
static void __exit exit_async_ops(void)
{
	// delete all the jobs in lists and dealloc memory
	struct completed_jobs_node *itr, *tmp;

	kfree(pwd);
	flush_workqueue(async_ops_wq);
	flush_workqueue(hp_async_ops_wq);

	cancel_delayed_work_sync(&job_for_cleanup_queue);
	flush_workqueue(cleanup_queue);

	destroy_workqueue(async_ops_wq);
	destroy_workqueue(hp_async_ops_wq);
	destroy_workqueue(cleanup_queue);

	list_for_each_entry_safe (itr, tmp, &completed_jobs, list) {
		list_del(&itr->list);
		if (operation_of_multiple_file_type(itr->op)) {
			var_arg_cleanup(itr->args);
		}
		kfree(itr);
	}

	proc_remove(async_ops_proc_entry);

	printk("Removed async_ops_module\n");
}

MODULE_AUTHOR("Aditi, Swetang and Yash");
module_init(init_async_ops);
module_exit(exit_async_ops);
MODULE_LICENSE("GPL");