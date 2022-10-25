#!/bin/bash
# Accepts the following runtime arguments: the first argument is a path to a 
# directory on the filesystem, referred to below as filesdir; the second 
# argument is a text string which will be searched within these files, 
# referred to below as searchstr
#
# Exits with return value 1 error and print statements if any of the parameters
# above were not specified
#
# Exits with return value 1 error and print statements if filesdir does not 
# represent a directory on the filesystem
#
# Prints a message "The number of files are X and the number of matching lines 
# are Y" where X is the number of files in the directory and all subdirectories
#  and Y is the number of matching lines found in respective files.

# Checks to see if both a directory and a search string are provided
if [ -z $1 ] || [ -z $2 ]
then
	echo ERROR: Please provide the path to a directory and the search string.
	exit 1
# Checks to see if the directory provided exists in the file system
elif [ ! -d $1 ]
then
	echo ERROR: The directory provided was not found.
	exit 1
else
	# Count the number of files by grepping with the count option to return
	# the number of occurences of the search string in each file, removing 
	# the zero results, and then counting the number of lines in the grep
	# output, resulting in one line counted per file with non-zero
	# occurences of the search string
	NUM_FILES=$( grep -rc $2 $1 | grep -v ':0$' | wc -l)
	# Count the number of matching lines by counting the number of lines 
	# in the grep output for the search string
	NUM_LINES=$( grep -r $2 $1 | wc -l )
	echo The number of files are $NUM_FILES and the number of matching lines are $NUM_LINES
fi
