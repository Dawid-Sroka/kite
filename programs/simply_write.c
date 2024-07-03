#include <unistd.h>

int main() {
  int fd = open("file.txt");
  write(fd);
  _exit();
}
