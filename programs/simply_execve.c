#include <unistd.h>

int main() {
  char *argv[] = { "./simply_write", NULL };
  char *envp[] = { NULL };
  execve("simply_exit", argv, envp);
  _exit(0);
}
