#include <unistd.h>

int main() {
  int pid = fork();
  if (pid == 0) { // child
    execve("simply_write");

  } else {        // parent
    //read();
    write();
  }
  _exit();
}
