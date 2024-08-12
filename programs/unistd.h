typedef unsigned int size_t;
void _exit();
void write(int fd);
int open(char* path);
void read(int fd, void* buf, size_t count);
void pipe(int pipefd[2]);
void execve(char* path);
int fork();
void wait();
int errno;

void debug_print(void* ptr);
