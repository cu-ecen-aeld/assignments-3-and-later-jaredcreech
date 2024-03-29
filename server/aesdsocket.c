#define _GNU_SOURCE
#define PORT "9000"         // the port users will be connecting to
#define BACKLOG 10          // how many pending connections queue will hold
#define MAXDATASIZE 1048576 // max number of bytes we can get at once
#if USE_AESD_CHAR_DEVICE
#define WR_PATH "/dev/"           // Path to write
#define FILE_PATH "/dev/aesdchar" // File to write
#define CHAR_DEVICE true
#else
#define WR_PATH "/var/tmp/"                 // Path to write
#define FILE_PATH "/var/tmp/aesdsocketdata" // File to write
#define CHAR_DEVICE false
#endif

#define IOCTL "AESDCHAR_IOCSEEKTO:"

#include "queue.h"
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
#include <pthread.h>
#include "../aesd-char-driver/aesd_ioctl.h"

typedef struct thread_data
{
    pthread_mutex_t *mutex;
    int new_fd;
    char *s;
} thread_data;

typedef struct slist_data_s slist_data_t;
struct slist_data_s
{
    pthread_t pthreadId;
    SLIST_ENTRY(slist_data_s)
    entries;
};

bool cleanShutdown = false;
int sockfd; // listen on sock_fd

// Handle signals for clean shutdown
void sigchld_handler(int s)
{
    printf("Caught signal %d...\n", s);

    if (s == SIGCHLD)
    {
        // waitpid() might overwrite errno, so we save and restore it:
        int saved_errno = errno;

        while (waitpid(-1, NULL, WNOHANG) > 0)
            ;

        errno = saved_errno;
    }
    else
    {
        syslog(LOG_INFO, "Caught signal, exiting");
        // Shutdown the socket connection
        shutdown(sockfd, SHUT_RDWR);
        cleanShutdown = true;
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

void *threadFunc(void *thread_param)
{
    int numbytes;          // number of bytes received
    char buf[MAXDATASIZE]; // socket receive buffer
    char *strtowr;         // string to write to file
    int i;                 // loop iterator
    thread_data *thread_func_args = (thread_data *)thread_param;
    bool ioctl_message = false;
    struct aesd_seekto seekto;
    int rv = 0; // return value

    // receive the string from the client
    if ((numbytes = recv(thread_func_args->new_fd, buf, MAXDATASIZE - 1, 0)) == -1)
    {
        perror("recv");
        close(thread_func_args->new_fd);
        pthread_exit((void *)EXIT_FAILURE);
    }

    // add NULL to end of buf so that it is a valid string
    buf[numbytes] = '\0';

    for (i = 0; i < sizeof(IOCTL - 1); i++)
    {
        if (buf[i] == IOCTL[i])
        {
            ioctl_message = true;
        }
        else
        {
            ioctl_message = false;
            break;
        }
    }

    // check for newline string terminator in received data
    if (buf[numbytes - 1] != '\n')
    {
        printf("\n\nrecv: Expected newline!!\n\n");
        close(thread_func_args->new_fd);
        pthread_exit((void *)EXIT_FAILURE);
    }

    // allocate memory for the received string
    strtowr = (char *)malloc((numbytes + 1) * sizeof(char));
    if (strtowr == NULL)
    {
        perror("malloc");
        pthread_exit((void *)EXIT_FAILURE);
    }

    // build the string to write
    for (i = 0; i <= numbytes; i++)
    {
        strtowr[i] = buf[i];
    }

    // lock the write to prevent interleaving from other threads
    pthread_mutex_lock(thread_func_args->mutex);

    // open the file to append the received data
    FILE *fp;
    fp = fopen(FILE_PATH, "a+");
    if (fp == NULL)
    {
        perror("fopen");
        pthread_exit((void *)EXIT_FAILURE);
    }

    if (ioctl_message == true)
    {
        printf("IOCTL MESSAGE = %s\n", strtowr);
        seekto.write_cmd = atoi(&strtowr[sizeof(IOCTL) - 1]);
        seekto.write_cmd_offset = atoi(&strtowr[sizeof(IOCTL) + 1]);
        rv = ioctl(fileno(fp), AESDCHAR_IOCSEEKTO, &seekto);
        printf("write_cmd = %d, write_cmd_offset = %d, ioctl rv=%d\n", seekto.write_cmd, seekto.write_cmd_offset, rv);
    }
    else
    {
        if (fputs(strtowr, fp) == EOF)
        {
            perror("fputs");
            pthread_mutex_unlock(thread_func_args->mutex);
            fclose(fp);
            pthread_exit((void *)EXIT_FAILURE);
        }
        fseek(fp, 0, SEEK_SET); // go to the beginning of the file
    }
    free(strtowr); // all done with this string

    // read back what you wrote
    memset(buf, 0, MAXDATASIZE * sizeof(buf[0])); // zeroize the receive buffer
    while (fgets(buf, MAXDATASIZE, fp) != NULL)
    {
        if (send(thread_func_args->new_fd, buf, strlen(buf), 0) == -1)
        {
            perror("send");
            pthread_mutex_unlock(thread_func_args->mutex);
            fclose(fp);
            pthread_exit((void *)EXIT_FAILURE);
        }
    }
    fclose(fp);
    pthread_mutex_unlock(thread_func_args->mutex);

    // done with the connection
    // printf("server: closed connection from %s\n", thread_func_args->s);
    syslog(LOG_INFO, "Closed connection from %s", thread_func_args->s);
    if (rv == 0)
    {
        pthread_exit((void *)EXIT_SUCCESS);
    }
    else
    {
        pthread_exit((void *)EXIT_FAILURE);
    }
}

void *write_timestamp(void *mutex)
{
    time_t t;
    struct tm *tmp;
    char MY_TIME[50];
    time(&t);
    tmp = localtime(&t);

    strftime(MY_TIME, sizeof(MY_TIME), "timestamp:%a, %d %b %y %T %z\n", tmp);

    // lock the write to prevent interleaving from other threads
    pthread_mutex_lock(mutex);

    // open the file to append the received data
    FILE *fp;
    fp = fopen(FILE_PATH, "a+");
    if (fp == NULL)
    {
        perror("fopen");
        pthread_exit((void *)EXIT_FAILURE);
    }

    if (fputs(MY_TIME, fp) == EOF)
    {
        perror("fputs");
        fclose(fp);
        pthread_mutex_unlock(mutex);
        pthread_exit((void *)EXIT_FAILURE);
    }
    fclose(fp);
    pthread_mutex_unlock(mutex);
    pthread_exit((void *)EXIT_SUCCESS);
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
    int exitCode = 0;
    bool runAsDaemon = false;
    pid_t pid;
    struct thread_data *thread_param;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

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

    // Setup Signal Handlers
    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("sigaction: SIGCHLD\n");
        exitCode = -1;
        cleanShutdown = true;
    }

    // shutdown cleanly when SIGINT received
    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction: SIGINT\n");
        exitCode = -1;
        cleanShutdown = true;
    }

    // shutdown cleanly when SIGTERM received
    if (sigaction(SIGTERM, &sa, NULL) == -1)
    {
        perror("sigaction: SIGTERM\n");
        exitCode = -1;
        cleanShutdown = true;
    }

    // shutdown cleanly when SIGPIPE received
    if (sigaction(SIGPIPE, &sa, NULL) == -1)
    {
        perror("sigaction: SIGPIPE\n");
        exitCode = -1;
        cleanShutdown = true;
    }

    if (listen(sockfd, BACKLOG) == -1)
    {
        perror("listen");
        exitCode = -1;
        cleanShutdown = true;
    }

    // setup daemon
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
            // printf("Parent process PID %d terminating.\n", pid);
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
            // printf("Parent process PID %d terminating.\n", pid);
            exitCode = 0;
            cleanShutdown = true;
        }

        // set new file permissions
        umask(0);

        // change the working directory to the root directory
        if (chdir("/") != 0)
        {
            perror("chdir");
            exitCode = -1;
            cleanShutdown = true;
        }

        // Close stdin. stdout and stderr
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        // open the log file
        openlog("aesdSocketDaemon", LOG_PID, LOG_DAEMON);
    }

    printf("server: CHAR_DEVICE = %d, waiting for connections...\n", CHAR_DEVICE);

    // setup the destination directory for writing
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

    // Setup Slist
    slist_data_t *datap = NULL;

    SLIST_HEAD(slisthead, slist_data_s)
    head;
    SLIST_INIT(&head);

    if (fork())
    {
        while ((cleanShutdown == false) && !CHAR_DEVICE)
        {
            int rv;
            rv = sleep(10);
            if (rv > 0)
            {
                printf("sleep returned %d\n", rv);
                cleanShutdown = true;
                break;
            }
            else
            {
                printf("timer went off\n");

                pthread_t tsPthreadId;
                if (pthread_create(&tsPthreadId, NULL, write_timestamp, &mutex) != 0)
                {
                    perror("ts pthread create");
                    return false;
                }
                int ts_rv;
                ts_rv = pthread_join(tsPthreadId, EXIT_SUCCESS);
                if (ts_rv != 0)
                {
                    perror("pthread_join, ts");
                    exitCode = -1;
                    cleanShutdown = true;
                }
            }
        }
        exitCode = 0;
    }

    while (cleanShutdown == false)
    {
        // main accept() loop
        usleep(50000);
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1)
        {
            continue;
        }
        inet_ntop(their_addr.ss_family,
                  get_in_addr((struct sockaddr *)&their_addr),
                  s, sizeof s);
        // printf("server: got connection from %s\n", s);
        syslog(LOG_INFO, "Accepted connection from %s", s);

        if (!fork()) // this is the child process
        {
            close(sockfd); // child doesn't need the listener

            // setup the struct for the connection handling thread
            thread_param = malloc(sizeof(struct thread_data));
            if (thread_param == NULL)
            {
                perror("malloc");
                exitCode = -1;
                cleanShutdown = true;
            }

            // address of the received connection
            thread_param->s = malloc(INET6_ADDRSTRLEN * sizeof(char));
            if (thread_param->s == NULL)
            {
                perror("malloc");
                exitCode = -1;
                cleanShutdown = true;
            }
            strcpy(thread_param->s, s);

            // mutex for writes
            thread_param->mutex = &mutex;

            // fd for accepted connection
            thread_param->new_fd = new_fd;

            // start the thread to handle the connection
            pthread_t pthreadId;
            int ret;
            ret = pthread_create(&pthreadId, NULL, threadFunc, (void *)thread_param);
            if (ret != 0)
            {
                perror("pthread_create");
                exitCode = -1;
                cleanShutdown = true;
            }
            else
            {
                datap = malloc(sizeof(slist_data_t));
                datap->pthreadId = pthreadId;
                SLIST_INSERT_HEAD(&head, datap, entries);
            }

            while (!SLIST_EMPTY(&head))
            {
                datap = SLIST_FIRST(&head);
                int tc_rv;
                tc_rv = pthread_join(datap->pthreadId, EXIT_SUCCESS);
                if (tc_rv != 0)
                {
                    perror("pthread_join");
                    exitCode = -1;
                    cleanShutdown = true;
                }
                SLIST_REMOVE_HEAD(&head, entries);
                free(datap);
                free(thread_param->s);
                free(thread_param);
            }
        }
    }

    while (cleanShutdown)
    {
        while (!SLIST_EMPTY(&head))
        {
            datap = SLIST_FIRST(&head);
            int tc_rv;
            tc_rv = pthread_join(datap->pthreadId, EXIT_SUCCESS);
            if (tc_rv != 0)
            {
                perror("ptread_join");
                exitCode = -1;
                cleanShutdown = true;
            }
            SLIST_REMOVE_HEAD(&head, entries);
            free(datap);
        }
        close(sockfd);
        if (!CHAR_DEVICE)
            remove(FILE_PATH);
        printf("\nExiting...\n");
        exit(exitCode);
    }
}