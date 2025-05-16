#include <unistd.h>

int main() {
  int fd = openat(AT_FDCWD, "file.log", O_CREAT | O_RDWR, 0644);
  int pid = fork();

  if (pid == 0) { // child
    char *argv[] = { "./simply_write", NULL };
    char *envp[] = { NULL };
    execve("simply_write", argv, envp);

  } else {        // parent
    char buf[10];
    write(fd, "test", 5);
    read(fd, buf, 5);
    write(2, buf, 10);
  }
  _exit(0);
}
