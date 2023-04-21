/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/slab.h> /* kmalloc() */
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <linux/mutex.h>
#include "aesdchar.h"
int aesd_major = 0; // use dynamic major
int aesd_minor = 0;

MODULE_AUTHOR("John Jared Creech"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev *aesd_device;

DEFINE_MUTEX(aesd_mutex);

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

void aesd_cleanup_module(void)
{
    int i;
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    PDEBUG("aesd_cleanup_module");
    cdev_del(&aesd_device->cdev);

    if (aesd_device->pwrite)
    {
        kfree(aesd_device->pwrite);
    }
    for (i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++)
    {
        if (aesd_device->buffer->entry[i].buffptr)
        {
            kfree(aesd_device->buffer->entry[i].buffptr);
        }
    }
    if (aesd_device->buffer)
    {
        kfree(aesd_device->buffer);
    }
    if (aesd_device)
    {
        kfree(aesd_device);
    }
    unregister_chrdev_region(devno, 1);
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                  loff_t *f_pos)
{
    char *kbuf;                                 // kernel read buffer
    size_t kbuf_offset = 0;                     // kernel read buffer offset
    long long int *mc_rv;                       // memcpy return value
    size_t kcount;                              // size of kernel read buffer
    int num_cb_reads;                           // number of circular buffer reads available
    struct aesd_buffer_entry *entry_offset_ptr; // pointer to the entry with the requested offset
    size_t entry_offset_byte;                   // byte to start at when returning the first entry
    ptrdiff_t entry_offset_start;               // start index of the entry containing the requested entry
    int entry_offset_index;                     // index of the entry containing the requested entry
    struct aesd_buffer_entry *entry;
    int i;                    // loop iterator
    ssize_t retval = -ENOMEM; // return value

    if (mutex_lock_interruptible(&aesd_mutex))
    {
        PDEBUG("aesd_read: could not get mutex");
        return -EINTR;
    }

    PDEBUG("aesd_read: read %zu bytes with offset %lld", count, *f_pos);

    // return the content of the most recent write commands
    // for (i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++)
    // {
    //     PDEBUG("aesd_read: read entry %d: %s", i, aesd_device->buffer->entry[i].buffptr);
    // }

    // figure out where to start reading
    entry_offset_ptr = aesd_circular_buffer_find_entry_offset_for_fpos(
        aesd_device->buffer,
        *f_pos,
        &entry_offset_byte);

    // if there's nothing in the buffer return ENOENT
    if ((entry_offset_ptr == NULL))
    {
        // PDEBUG("aesd_read: entry_offset_ptr: %p", entry_offset_ptr);
        mutex_unlock(&aesd_mutex);
        return 0;
    }

    // do pointer math to find out which index was returned
    entry_offset_start = entry_offset_ptr - aesd_device->buffer->entry;
    // PDEBUG("aesd_read: entry_offset_start = %ld", entry_offset_start);

    // determine how many entries to pull from the circular buffer
    if (aesd_device->buffer->full == true)
    {
        num_cb_reads = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
    else
    // if the buffer is not full, determine the distance from the
    // in and out pointers and read that many entries
    {
        num_cb_reads = aesd_device->buffer->in_offs - aesd_device->buffer->out_offs;
    }
    // PDEBUG("aesd_read: num_cb_reads = %d", num_cb_reads);

    // create a kernel buffer for the read of size count
    kbuf = (char *)kmalloc(count, GFP_KERNEL);
    if (kbuf == NULL)
    {
        retval = -ENOMEM;
        printk(KERN_ERR "ENOMEM on read kmalloc");
        mutex_unlock(&aesd_mutex);
        return retval;
    }
    memset(kbuf, 0, count * sizeof(char));

    // retrieve the data from the aesd device and put it in the kernel buffer
    for (i = 0; i < num_cb_reads; i++)
    {
        entry_offset_index = (entry_offset_start + i) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        // PDEBUG("aesd_read: i = %d", i);

        // allocate memory for the buffer entry
        entry = kmalloc(sizeof(struct aesd_buffer_entry), GFP_KERNEL);
        if (!entry)
        {
            retval = -ENOMEM;
            printk(KERN_ERR "aesd_read: ENOMEM on entry kmalloc");
            goto fail;
        }

        if (i == 0)
        {
            // copy the data from the circular buffer to the kernel buffer, omitting any file offset
            entry->buffptr = aesd_device->buffer->entry[entry_offset_index].buffptr + (*f_pos * sizeof(char));
            entry->size = aesd_device->buffer->entry[entry_offset_index].size - *f_pos;
        }
        else
        {
            // copy the data from the circular buffer to the kernel buffer
            entry->buffptr = aesd_device->buffer->entry[entry_offset_index].buffptr;
            entry->size = aesd_device->buffer->entry[entry_offset_index].size;
        }
        // PDEBUG("aesd_read: entry->buffptr = %s", entry->buffptr);
        // PDEBUG("aesd_read: entry->size = %ld", entry->size);

        mc_rv = memcpy(kbuf + kbuf_offset, entry->buffptr, entry->size);
        if (mc_rv == NULL)
        {
            retval = -EFAULT;
            PDEBUG("aesd_read: failed memcpy");
            goto fail;
        }
        // update the kernel buffer offset for the next entry
        kbuf_offset = kbuf_offset + entry->size;
        // PDEBUG("aesd_read: kbuf_offset = %ld", kbuf_offset);
        kfree(entry);
    }

    PDEBUG("aesd_read: kbuf = \n%s", kbuf);
    kcount = simple_read_from_buffer(buf, count, f_pos, kbuf, kbuf_offset);

    PDEBUG("aesd_read: kcount = %ld", kcount);

    // done with the read, free the memory;
    kfree(kbuf);
    mutex_unlock(&aesd_mutex);
    return kcount;

fail:
    if (entry)
        kfree(entry);
    kfree(kbuf);
    mutex_unlock(&aesd_mutex);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                   loff_t *f_pos)
{
    // struct aesd_buffer_entry *entry;
    char *kbuf;    // kernel write buffer
    size_t kcount; // kernel write count
    ssize_t retval = -ENOMEM;
    unsigned long cfu_rv; // copy from user return value
    long long int *mc_rv; // memcpy return value
    struct aesd_buffer_entry *entry;
    // int i;

    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);
    if (mutex_lock_interruptible(&aesd_mutex))
    {
        PDEBUG("aesd_write: could not get mutex");
        return -EINTR;
    }

    // size of write is count plus current pwrite size
    kcount = count + aesd_device->pwrite->size;

    // allocate kernel memory for the write
    kbuf = (char *)kmalloc(kcount, GFP_KERNEL);
    if (kbuf == NULL)
    {
        retval = -ENOMEM;
        printk(KERN_ERR "ENOMEM on entry kmalloc");
        mutex_unlock(&aesd_mutex);
        return retval;
    }

    // if there is a partial write, copy that into the kernel buffer first
    if (aesd_device->pwrite->size > 0)
    {
        mc_rv = memcpy(kbuf, aesd_device->pwrite->buffptr, aesd_device->pwrite->size);
        if (mc_rv == NULL)
        {
            retval = -EFAULT;
            PDEBUG("failed memcpy");
            goto fail;
        }
        // done with this buffer
        kfree(aesd_device->pwrite->buffptr);
        aesd_device->pwrite->size = 0;
    }

    // copy the user buffer to kernel space and account for any partial write
    cfu_rv = copy_from_user(kbuf + aesd_device->pwrite->size, buf, count);
    if (cfu_rv != 0)
    {
        retval = -EFAULT;
        PDEBUG("failed copy_from_user with %lu bytes\n", cfu_rv);
        goto fail;
    }
    PDEBUG("Kernel string: %s", kbuf);

    // if this is not a complete write, put it into the partial write buffer
    if (kbuf[kcount - 1] != '\n')
    {
        // allocate memory for the partial write
        aesd_device->pwrite->buffptr = (char *)kmalloc(kcount, GFP_KERNEL);
        if (aesd_device->pwrite->buffptr == NULL)
        {
            retval = -ENOMEM;
            printk(KERN_ERR "ENOMEM on kernel pwrite buffer kmalloc");
            mutex_unlock(&aesd_mutex);
            return retval;
        }
        // copy the partial write into the pwrite buffer in kernel
        mc_rv = memcpy(kbuf, aesd_device->pwrite->buffptr, kcount);
        if (mc_rv == NULL)
        {
            retval = -EFAULT;
            PDEBUG("failed memcpy");
            goto fail;
        }
        aesd_device->pwrite->size = kcount;

        // return the number of bytes from this write
        mutex_unlock(&aesd_mutex);
        return count;
    }
    else // for complete writes, place the entry into the circular buffer
    {
        // if the buffer is full, delete the current entry before overwriting it
        if (aesd_device->buffer->full == true)
        {
            kfree(aesd_device->buffer->entry[aesd_device->buffer->in_offs].buffptr);
        }

        // allocate memory for the buffer entry
        entry = kmalloc(sizeof(struct aesd_buffer_entry), GFP_KERNEL);
        if (!entry)
        {
            retval = -ENOMEM;
            printk(KERN_ERR "ENOMEM on entry kmalloc");
            goto fail;
        }

        // create buffer entry
        entry->buffptr = kbuf;
        entry->size = kcount;

        // insert the buffer entry into the circular buffer
        aesd_circular_buffer_add_entry(aesd_device->buffer, entry);
        // for (i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++)
        // {
        //     PDEBUG("aesd_write: in=%d, out=%d, entry[%d]=%s",
        //     aesd_device->buffer->in_offs, aesd_device->buffer->out_offs, i, aesd_device->buffer->entry[i].buffptr);
        // }

        // return the number of bytes for this write
        mutex_unlock(&aesd_mutex);
        return count;
    }

fail:
    if (aesd_device->pwrite->buffptr)
        kfree(aesd_device->pwrite->buffptr);
    if (entry)
        kfree(entry);
    kfree(kbuf);
    mutex_unlock(&aesd_mutex);
    return count;
}
struct file_operations aesd_fops = {
    .owner = THIS_MODULE,
    .read = aesd_read,
    .write = aesd_write,
    .open = aesd_open,
    .release = aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add(&dev->cdev, devno, 1);
    if (err)
    {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;

    PDEBUG("Running aesd_init_module\n");
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
                                 "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0)
    {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    aesd_device = kmalloc(sizeof(struct aesd_dev), GFP_KERNEL);
    if (!aesd_device)
    {
        result = -ENOMEM;
        printk(KERN_ERR "ENOMEM on aesd_device kmalloc");
        goto fail;
    }
    memset(aesd_device, 0, sizeof(struct aesd_dev));

    aesd_device->buffer = kmalloc(sizeof(struct aesd_circular_buffer), GFP_KERNEL);
    if (!aesd_device->buffer)
    {
        result = -ENOMEM;
        printk(KERN_ERR "ENOMEM on aesd_device.buffer kmalloc");
        goto fail;
    }
    memset(aesd_device->buffer, 0, sizeof(struct aesd_circular_buffer));

    aesd_device->pwrite = kmalloc(sizeof(struct aesd_buffer_entry), GFP_KERNEL);
    if (!aesd_device->pwrite)
    {
        result = -ENOMEM;
        printk(KERN_ERR "ENOMEM on aesd_device.pwrite kmalloc");
        goto fail;
    }
    memset(aesd_device->pwrite, 0, sizeof(struct aesd_buffer_entry));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    aesd_circular_buffer_init(aesd_device->buffer);
    aesd_device->pwrite->size = 0;

    result = aesd_setup_cdev(aesd_device);

    if (result)
    {
        unregister_chrdev_region(dev, 1);
    }
    return result;

fail:
    aesd_cleanup_module();
    return result;
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
