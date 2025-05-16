#include <unistd.h>

int main() {
  int fd = openat(AT_FDCWD, "myfile.txt", O_CREAT | O_WRONLY, 0644);
  write(fd, "message", 8);
  _exit(0);
}
