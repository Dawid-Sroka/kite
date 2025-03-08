#include <unistd.h>

int main() {

  int pipefd[2];
  pipe(pipefd);

  int pid = fork();

  if (pid == 0) { // child
    write(2, "child\n", 6);
    char* message = "written\n";
    int n = write(pipefd[1], message, 8);
    write(2, "no bytes written = ", 19);
    n += 48;
    write(2, &n, 1);
    write(2, "\n", 1);

  } else {        // parent
    write(2, "parent before read\n", 19);
    char buf[10];
    size_t bytes_read = read(pipefd[0], buf, 5);
    write(2, "buf after read = ", 17);
    write(2, buf, 10);
    write(2, "\n", 1);
  }
  _exit();
}
