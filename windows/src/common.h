
char * offset_file_name(char *file_path);
int sanitize_file_name(char *name);

int get_absolute_path(char *absolute_path, char *relative_path, size_t max);
size_t path_copy(char *dst, char *src, size_t max);

int namez_add(char **namez, size_t *namez_len, size_t *namez_max, const char *str);
int namez_count(char *namez, size_t namez_len);
int namez_delete(char *namez, size_t *namez_len, char *entry);
char * namez_search(char *namez, size_t namez_len, char *match);
char * namez_get(char *namez, size_t namez_len, int index);
int namez_sort(char *namez, size_t namez_len);
size_t namez_maxlen(char *namez, size_t namez_len);

int mem_or8(unsigned char buf[8]);
int mem_or16(unsigned char buf[16]);

int popcount32(uint32_t x);
int int_log2(uint64_t x);

