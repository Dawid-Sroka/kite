#include <unistd.h>

int main() {
  execve("simply_exit");
  _exit();
}
