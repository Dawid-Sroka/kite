typedef unsigned int size_t;
void _exit();
size_t write(int fd, const void* buf, size_t count);
int open(char* path);
size_t read(int fd, void* buf, size_t count);
void pipe(int pipefd[2]);
void execve(char* path);
int fork();
void wait();
int errno;

void debug_print(void* ptr);
