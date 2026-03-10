#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>

unsigned char *read_binary_file(const char *filename, size_t *size);
int write_binary_file(const char *filename, const unsigned char *data, size_t size);

#endif