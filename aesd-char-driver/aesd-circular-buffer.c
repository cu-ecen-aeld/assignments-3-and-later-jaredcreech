/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

#include <stdio.h>

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
int buffer_empty_flag;

struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
                                                                          size_t char_offset, size_t *entry_offset_byte_rtn)
{
    /**
     * TODO: implement per description
     */
    int i = 0;
    size_t offset_accumulator = 0;
    int offset_entry_pointer;

    // handle the case that the buffer is empty
    if (buffer_empty_flag == 1)
    {
        // printf("The buffer is empty!\n");
        return NULL;
    }

    for (i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++)
    {
        // The offset entry pointer is the current entry in the loop when counting from the out offset pointer
        offset_entry_pointer = (buffer->out_offs + i) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

        // The offset accumulator is the accumulation of all entry sizes while iterating
        offset_accumulator = offset_accumulator + buffer->entry[offset_entry_pointer].size;

        // if the offset accumulator is larger than the provided character offset, then the character
        // offset is in the current entry
        if (offset_accumulator > char_offset)
        {
            // the entry offset byte is the difference between the char offset and the offset accumulator value
            // in the last iteration
            // printf("READ: offset_accumulator = %ld; ", offset_accumulator);
            *entry_offset_byte_rtn = char_offset - (offset_accumulator - buffer->entry[offset_entry_pointer].size);
            // printf("READ: *entry_offset_byte_rtn = %ld; ", *entry_offset_byte_rtn);
            // printf("buffer->entry[%d].buffptr = %s", offset_entry_pointer, buffer->entry[offset_entry_pointer].buffptr);
            return &buffer->entry[offset_entry_pointer];
        }
    }

    // if the loop finishes without returning, the value wasn't found
    // printf("No entry for char_offset = %ld found \n", char_offset);
    return NULL;
}

/**
 * Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
 * If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
 * new start location.
 * Any necessary locking must be handled by the caller
 * Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
 */
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    // if the buffer isn't empty, and the in and out pointers match, that means it's full
    // and the out pointer needs to advance so that the oldest item in the buffer can be overwritten
    if (buffer_empty_flag == 0)
    {
        if (buffer->in_offs == buffer->out_offs)
        {
            buffer->full = true;
            buffer->out_offs = buffer->out_offs + 1;
            buffer->out_offs = buffer->out_offs % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; // ensure pointer wraps around
        }
    }

    // buffer entry pointer gets the address and size of the entry at the current in pointer, overwriting any
    // previous data
    buffer->entry[buffer->in_offs].buffptr = add_entry->buffptr;
    buffer->entry[buffer->in_offs].size = add_entry->size;
    // printf("WRITE: buffer->entry[%d].buffptr = %s", buffer->in_offs, buffer->entry[buffer->in_offs].buffptr);

    buffer->in_offs = buffer->in_offs + 1;
    buffer->in_offs = buffer->in_offs % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; // ensure the pointer wraps around

    // clear the empty flag on the first write
    buffer_empty_flag = 0;
}

/**
 * Initializes the circular buffer described by @param buffer to an empty struct
 */
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer, 0, sizeof(struct aesd_circular_buffer));
    buffer->in_offs = 0;
    buffer->out_offs = 0;
    buffer->full = false;
    buffer_empty_flag = 1; // set the empty flag on init
}
