#include <unistd.h>

int main() {
  int pid = fork();
  if (pid == 0) { // child
    execve("simply_write");

  } else {        // parent
    int fd = open("file.txt");
    read(fd);
  }
  _exit();
}
