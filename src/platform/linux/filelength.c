#include "platform_linux.h"

#include <sys/stat.h>
#include <stdint.h>

int64_t _filelengthi64(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0) return -1;  // failure
    return st.st_size;
}
