#include <unistd.h>

int main() {
  fork();
  // execve("simply_exit");
  _exit();
}
