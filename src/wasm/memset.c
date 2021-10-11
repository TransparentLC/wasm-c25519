#include <stddef.h>

void *memset(void *str, int c, size_t n) {
  unsigned char *s = (unsigned char *)str;
  while(n--) *s++ = c;
  return str;
}