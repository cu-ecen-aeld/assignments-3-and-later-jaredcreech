#define _GNU_SOURCE
#define PORT "9000"                         // the port users will be connecting to
#define BACKLOG 10                          // how many pending connections queue will hold
#define MAXDATASIZE 1048576                 // max number of bytes we can get at once
#define WR_PATH "/var/tmp/"                 // Path to write
#define FILE_PATH "/var/tmp/aesdsocketdata" // File to write

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <syslog.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdbool.h>

bool cleanShutdown = false;
int sockfd; // listen on sock_fd

void sigchld_handler(int s)
{
    syslog(LOG_INFO, "Caught signal, exiting");
    shutdown(sockfd, SHUT_RDWR);
    cleanShutdown = true;

    if (s == SIGCHLD)
    {
        // waitpid() might overwrite errno, so we save and restore it:
        int saved_errno = errno;

        while (waitpid(-1, NULL, WNOHANG) > 0)
            ;

        errno = saved_errno;
    }
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int main(int argc, char **argv)
{
    int new_fd; // new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;
    char buf[MAXDATASIZE]; // socket receive buffer
    int numbytes;          // number of bytes received
    char *strtowr;         // string to write to file
    int i, exitCode;
    bool runAsDaemon = false;
    pid_t pid;

    // check if run as daemon argument was supplied
    if (argc == 2)
    {
        if (strcmp(argv[1], "-d") == 0)
        {
            runAsDaemon = true;
        }
        else
        {
            printf("Unexpected argument '%s'.\n", argv[1]);
            exit(-1);
        }
    }
    else if (argc > 2)
    {
        printf("Too many arguments.\n");
        exit(-1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1)
        {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            perror("setsockopt");
            exit(-1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)
    {
        fprintf(stderr, "server: failed to bind\n");
        exit(-1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("sigaction: SIGCHLD\n");
        exitCode = -1;
        cleanShutdown = true;
    }
    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction: SIGINT\n");
        exitCode = -1;
        cleanShutdown = true;
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1)
    {
        perror("sigaction: SIGTERM\n");
        exitCode = -1;
        cleanShutdown = true;
    }

    if (listen(sockfd, BACKLOG) == -1)
    {
        perror("listen");
        exitCode = -1;
        cleanShutdown = true;
    }

    if (runAsDaemon == true)
    {
        pid = fork(); // fork off the parent process
        if (pid < 0)  // an error occured
        {
            perror("fork");
            exitCode = -1;
            cleanShutdown = true;
        }
        else if (pid > 0) // success: let the parent terminate
        {
            printf("Parent process PID %d terminating.", pid);
            exitCode = 0;
            cleanShutdown = true;
        }

        // child process becomes session leader
        if (setsid() < 0)
        {
            perror("setsid");
            exitCode = -1;
            cleanShutdown = true;
        }

        pid = fork(); // fork off the parent process
        if (pid < 0)  // an error occured
        {
            perror("fork");
            exitCode = -1;
            cleanShutdown = true;
        }
        else if (pid > 0) // success: let the parent terminate
        {
            printf("Parent process PID %d terminating.\n", pid);
            exitCode = 0;
            cleanShutdown = true;
        }

        // set new file permissions
        umask(0);

        // change the working directory to the root directory
        chdir("/");

        // Close stdin. stdout and stderr
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        // open the log file
        openlog("aesdSocketDaemon", LOG_PID, LOG_DAEMON);
    }

    printf("server: waiting for connections...\n");

    DIR *dir = opendir(WR_PATH);
    if (dir)
    {
        // Directory exists
        syslog(LOG_INFO, "Info: Directory already exists at %s", WR_PATH);
        closedir(dir);
    }
    else if (ENOENT == errno)
    {
        // Directory does not exist
        syslog(LOG_INFO, "Info: Creating directory %s.", WR_PATH);
        mkdir(WR_PATH, 0777);
    }
    else
    {
        // Something else happened
        syslog(LOG_ERR, "ERROR: Could not access or create directory at %s.", WR_PATH);
        exitCode = -1;
        cleanShutdown = true;
    }

    while (cleanShutdown == false)
    { // main accept() loop
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1)
        {
            //perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
                  get_in_addr((struct sockaddr *)&their_addr),
                  s, sizeof s);
        printf("server: got connection from %s\n", s);
        syslog(LOG_INFO, "Accepted connection from %s", s);

        if (!fork())
        {
            // this is the child process
            close(sockfd); // child doesn't need the listener

            // receive the string from the client
            if ((numbytes = recv(new_fd, buf, MAXDATASIZE - 1, 0)) == -1)
            {
                perror("recv");
                close(new_fd);
                exit(-1);
            }
            buf[numbytes] = '\0'; // add NULL to end of buf for valid string
            printf("server: received %s", buf);
            if (buf[numbytes - 1] != '\n')
            {
                perror("\n\nrecv: Expected newline\n\n");
                close(new_fd);
                exit(-1);
            }

            // write the string to the file
            strtowr = (char *)malloc(numbytes * sizeof(char));
            if (strtowr == NULL)
            {
                perror("malloc");
                exit(-1);
            }
            for (i = 0; i <= numbytes; i++)
            {
                strtowr[i] = buf[i];
            }
            FILE *fp;
            fp = fopen(FILE_PATH, "a+");
            if (fp == NULL)
            {
                perror("fopen");
                exit(-1);
            }
            if (fputs(strtowr, fp) == EOF)
            {
                perror("fputs");
                exit(-1);
            }
            free(strtowr);

            // read back what you got
            fseek(fp, 0, SEEK_SET);                       // go to the beginning of the file
            memset(buf, 0, MAXDATASIZE * sizeof(buf[0])); // zeroize the receive buffer
            while (fgets(buf, MAXDATASIZE, fp) != NULL)
            {
                printf("read from file: %s", buf);
                if (send(new_fd, buf, strlen(buf), 0) == -1)
                    perror("send");
            }
            fclose(fp);
        }
        close(new_fd); // parent doesn't need this
        printf("server: closed connection from %s\n", s);
        syslog(LOG_INFO, "Closed connection from %s", s);
    }

    while (cleanShutdown)
    {
        close(new_fd);
        close(sockfd);
        syslog(LOG_INFO, "Closed connection from %s", s);
        remove(FILE_PATH);
        printf("\nExiting...\n");
        exit(exitCode);
    }
}