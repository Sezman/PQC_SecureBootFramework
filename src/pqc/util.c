#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stddef.h>

/* ===== timer.h ===== */
long get_time_us();

/* ===== util.h ===== */
unsigned char *read_binary_file(const char *filename, size_t *size);
int write_binary_file(const char *filename, const unsigned char *data, size_t size);

/* ===== timer.c ===== */
long get_time_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000L + tv.tv_usec;
}

/* ===== util.c ===== */
unsigned char *read_binary_file(const char *filename, size_t *size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("fopen");
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }

    long file_size = ftell(file);
    if (file_size < 0) {
        fclose(file);
        return NULL;
    }

    rewind(file);

    unsigned char *buffer = NULL;
    if (file_size == 0) {
        buffer = malloc(1);
        if (!buffer) {
            fclose(file);
            return NULL;
        }
        *size = 0;
        fclose(file);
        return buffer;
    }

    buffer = malloc((size_t)file_size);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    size_t bytes_read = fread(buffer, 1, (size_t)file_size, file);
    fclose(file);

    if (bytes_read != (size_t)file_size) {
        free(buffer);
        return NULL;
    }

    *size = (size_t)file_size;
    return buffer;
}

int write_binary_file(const char *filename, const unsigned char *data, size_t size) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("fopen");
        return 0;
    }

    size_t bytes_written = fwrite(data, 1, size, file);
    fclose(file);

    return bytes_written == size;
}