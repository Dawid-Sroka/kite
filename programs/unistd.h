#define NULL 0
#define AT_FDCWD -100
#define O_CREAT 0x200
#define O_WRONLY 0x1
#define O_RDWR 0x2

typedef unsigned int size_t;
void _exit();
size_t write(int fd, const void* buf, size_t count);
int openat(int dirfd, const char *pathname, int flags, int mode);
size_t read(int fd, void* buf, size_t count);
int pipe2(int pipefd[2], int flags);
int execve(const char *pathname, char *const argv[], char *const envp[]);
int fork();
int sigsuspend(int *mask);
int errno;

void debug_print(void* ptr);
