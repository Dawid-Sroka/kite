#include <unistd.h>

int main() {
  int* a;
  a = NULL;
  int b = *a;

  _exit(0);
}
