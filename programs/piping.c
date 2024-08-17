#include <unistd.h>

int main() {

  int pipefd[2];
  pipe(pipefd);

  int pid = fork();

  if (pid == 0) { // child
    write(pipefd[1]);

  } else {        // parent
    char buf[10];
    read(pipefd[0], buf, 5);
  }
  _exit();
}
