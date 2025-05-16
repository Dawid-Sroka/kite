#include <unistd.h>

int main() {

  int pipefd[2];
  pipe2(pipefd, 0);

  int pid = fork();

  if (pid == 0) { // child
    write(pipefd[1], "hey", 4);

  } else {        // parent
    sigsuspend(0);
  }
  _exit(0);
}
