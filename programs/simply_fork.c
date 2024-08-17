#include <unistd.h>

int main() {
  int pid = fork();
  if (pid == 0) { // child
    execve("simply_write");

  } else {        // parent
    int fd = open("file.txt");
    char buf[10];
    read(fd, buf, 5);
  }
  _exit();
}
