#include <unistd.h>

int main() {
  int fd = open("file.log");
  write(fd, "message", 8);
  _exit();
}
