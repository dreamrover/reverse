#include <linux/list.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/timer.h>
//#include <linux/kallsyms.h>
#include <linux/signal.h>
#include <linux/string.h>
//#include <linux/kernel.h>
//#include <linux/syscalls.h>
//#include <linux/unistd.h>
//#include <asm/unistd.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/wait.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <linux/slab.h>

struct reverse_buffer {
    char *data;
    char *end;
    char *read_ptr;
    unsigned long size;
    wait_queue_head_t read_queue;
};

static unsigned long buffer_size = PAGE_SIZE;
module_param(buffer_size, ulong, 0444);
MODULE_PARM_DESC(buffer_size, "Buffer Size.");

//char page[PAGE_SIZE] = "abcdefghijklmnopqrstuvwxyz";
char *page;

static struct reverse_buffer *reverse_buffer_alloc(unsigned long size)
{
    struct reverse_buffer *buf;
    buf = kzalloc(sizeof(*buf), GFP_KERNEL);
    if (unlikely(!buf))
        goto out;
    buf->data = kzalloc(size, GFP_KERNEL);
    if (unlikely(!buf->data))
        goto out;
    init_waitqueue_head(&buf->read_queue);
out:
    return buf;
}

static int reverse_buffer_free(struct reverse_buffer *buf)
{
    int err = 0;

    if (!buf)
    {
        err = -1;
        goto out;
    }
    if (buf->data)
    {
        kfree(buf->data);
    }
    kfree(buf);
out:
    return err;
}

static int reverse_open(struct inode *inode, struct file *filp)
{
    int err = 0;
    filp->private_data = reverse_buffer_alloc(buffer_size);
    if (!filp->private_data)
        err = -ENOMEM;
    return err;
}

static int reverse_release(struct inode *inode, struct file *filp)
{
    return reverse_buffer_free(filp->private_data);
}

static ssize_t reverse_read(struct file *filp, char __user *out, size_t size, loff_t *off)
{
    struct reverse_buffer *buf = filp->private_data;
    ssize_t result;

    while (buf->read_ptr == buf->end)
    {
        if (filp->f_flags & O_NONBLOCK)
        {
            result = -EAGAIN;
            goto out;
        }
        if (wait_event_interruptible(buf->read_queue, buf->read_ptr != buf->end))
        {
            result = -ERESTARTSYS;
            goto out;
        }
    }
    size = min(size, (size_t)(buf->end - buf->read_ptr));
    if (copy_to_user(out, buf->read_ptr, size))
    {
        result = -EFAULT;
        goto out;
    }
    buf->read_ptr += size;
    result = size;
out:
    return result;
}

static void reverse_phrase(char *head, char *tail)
{
    while (head < tail)
    {
        *head ^= *tail;
        *tail ^= *head;
        *head++ ^= *tail--;
    }
}

static ssize_t reverse_write(struct file *filp, const char __user *in, size_t size, loff_t *off)
{
    struct reverse_buffer *buf = filp->private_data;
    ssize_t result;

    if (size > buffer_size)
    {
        result = -1;
        goto out;
    }
    /*if (!buf->data)
    {
        buf->data = kzalloc(buffer_size, GFP_KERNEL);
        if (!buf->data)
        {
            result = -1;
            goto out;
        }
    }*/
    if (copy_from_user(buf->data, in, size))
    {
        result = -EFAULT;
        goto out;
    }
    buf->end = buf->data + size;
    buf->read_ptr = buf->data;
    result = size;
    if (buf->end > buf->data)
        reverse_phrase(buf->data, buf->end - 1);
    memset(page, 0, buffer_size);
    memcpy(page, buf->data, size);
    wake_up_interruptible(&buf->read_queue);
out:
    return result;
}

static struct file_operations reverse_fops = {
    .owner = THIS_MODULE,
    .llseek = noop_llseek, // do nothing
    .read = reverse_read,
    .write = reverse_write,
    .open = reverse_open,
    .release = reverse_release
};

static struct miscdevice reverse_misc_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "reverse",
    .fops = &reverse_fops,
    .mode = 0666 // ??
};

static int reverse_read_proc(char *buf, char **start, off_t off, int count, int *eof, void *data)
{
    int len, nr;

    len = strlen(page);
    if (len <= off)
    {
        nr = 0;
        *eof = 1;
    }
    else if (len < off+count)
    {
        strcpy(buf, page+off);
        nr = len - off;
    }
    else
    {
        strncpy(buf, page+off, count);
        nr = count;
    }
    return nr;
}

static int reverse_write_proc(struct file *filp, const char __user *buffer, unsigned long count, void *data)
{
    char *buf;
    int ret = count;

    if (count > buffer_size)
    {
        ret = -1;
        goto out;
    }
    buf = kzalloc(count, GFP_KERNEL);
    if (!buf)
    {
        ret = -1;
        goto out;
    }
    if (copy_from_user(buf, buffer, count))
    {
        ret = -EFAULT;
        goto out;
    }
    reverse_phrase(buf, buf + count - 1);
    memset(page, 0, buffer_size);
    memcpy(page, buf, count);
    kfree(buf);
out:
    return ret;
}

struct proc_dir_entry *proc_entry;

static int __init reverse_init(void)
{
    if (!buffer_size)
        return -1;
    misc_register(&reverse_misc_device);
    page = kzalloc(buffer_size, GFP_KERNEL);
    if (!page)
        goto out;
    //create_proc_read_entry("reverse", 0, NULL, reverse_read_proc, NULL);
    //strcpy(page, "abcdefghijklmnopqrstuvwxyz");
    proc_entry = create_proc_entry("reverse", 0644, NULL);
    //proc_entry = proc_create_data("reverse", 0644, NULL, NULL, NULL);
    if (!proc_entry)
        goto out;
    proc_entry->read_proc = reverse_read_proc;
    proc_entry->write_proc = reverse_write_proc;
out:
    return 0;
}

static void __exit reverse_exit(void)
{
    misc_deregister(&reverse_misc_device);
    if (page)
    {
        kfree(page);
        if (proc_entry)
            remove_proc_entry("reverse", NULL);
    }
}

module_init(reverse_init);
module_exit(reverse_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Reverse");
MODULE_AUTHOR("Anonymous");
