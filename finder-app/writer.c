/*
Accepts the following arguments: the first argument is a full path to a file
(including filename) on the filesystem, referred to below as writefile; the
second argument is a text string which will be written within this file,
referred to below as writestr

Exits with value 1 error and print statements if any of the arguments above
were not specified

Creates a new file with name and path writefile with content writestr,
overwriting any existing file and creating the path if it doesn’t exist.
Exits with value 1 and error print statement if the file could not be created.
*/

#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>

int main(int argc, char *argv[])
{
	openlog(NULL,0,LOG_USER);
	// Checks to see if both a path and a text string are provided
	if (argc < 3 || argc > 3)
	{
		syslog(LOG_ERR, "ERROR: Invalid Number of arguments, expected '3', got '%d'.", argc);
		return 1;
	}
	else
	{
		// Check to see if provided directory already exists
		// then create the directory if it does not exist
		char *path = argv[1];
		char *dname = NULL;
		dname = strdup(path);
		dname = dirname(dname);

		DIR *dir = opendir(dname);
		if (dir)
		{
			// Directory exists
			syslog(LOG_INFO, "Info: Directory already exists at %s", dname);
			closedir(dir);
		}
		else if (ENOENT == errno)
		{
			// Directory does not exist
			syslog(LOG_INFO, "Info: Creating directory %s.", dname);
			mkdir(dname, 0777);
			free(dname);
		}
		else
		{
			// Something else happened
			syslog(LOG_ERR, "ERROR: Could not access or create directory at %s.", dname);
			return 1;
		}

		// Write the file
		char *string = argv[2];
		char *fname = NULL;
		fname = strdup(path);
		fname = basename(fname);
		syslog(LOG_DEBUG, "Writing %s to %s", string, fname);
		FILE *fp;
		fp = fopen(path, "w+");
		fputs(string, fp);
		fclose(fp);
		
		return 0;
	}
}
