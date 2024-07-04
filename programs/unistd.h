void _exit();
void write(int fd);
int open(char* path);
void read(int fd);
void pipe(int pipefd[2]);
void execve(char* path);
int fork();
int errno;
