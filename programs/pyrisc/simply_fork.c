#include <unistd.h>

int main() {
  int fd = open("file.log");
  int pid = fork();

  if (pid == 0) { // child
    execve("simply_write");

  } else {        // parent
    char buf[10];
    read(fd, buf, 5);
    write(2, buf, 10);
  }
  _exit();
}
