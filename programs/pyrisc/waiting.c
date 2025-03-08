#include <unistd.h>

int main() {

  int pipefd[2];
  pipe(pipefd);

  int pid = fork();

  if (pid == 0) { // child
    write(pipefd[1], "hey", 4);

  } else {        // parent
    wait();
  }
  _exit();
}
