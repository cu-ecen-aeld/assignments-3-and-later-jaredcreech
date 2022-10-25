#!/bin/bash
# Accepts the following arguments: the first argument is a full path to a file 
# (including filename) on the filesystem, referred to below as writefile; the 
# second argument is a text string which will be written within this file,
# referred to below as writestr

# Exits with value 1 error and print statements if any of the arguments above
# were not specified

# Creates a new file with name and path writefile with content writestr, 
# overwriting any existing file and creating the path if it doesn’t exist. 
# Exits with value 1 and error print statement if the file could not be created.

# Checks to see if both a path and a text string are provided
if [ -z $1 ] || [ -z $2 ]
then
	echo ERROR: Please provide the path to a file and the text string to write.
	exit 1
else
	# Create the directory if it doesn't exist
	mkdir -p $(dirname $1)
	if [ $? -gt 0 ]
	then
		echo ERROR: Could not create directory at that location
		exit 1
	fi
	# Check if we have permission to write	
	touch $1
	if [ $? -gt 0 ]
	then
		echo ERROR: Cannot write to $1 -- permission denied.
		exit 1
	else
		# Out with the old
		rm -f $1
		# in with the new
		echo $2 > $1
	fi
fi
