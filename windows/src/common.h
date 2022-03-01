
char * offset_file_name(char *file_path);
int get_absolute_path(char *absolute_path, char *relative_path, size_t max);
size_t path_copy(char *dst, char *src, size_t max);

int namez_add(char **namez, size_t *namez_len, size_t *namez_max, const char *str);
int namez_count(char *namez, size_t namez_len);
int namez_delete(char *namez, size_t *namez_len, char *entry);
char * namez_search(char *namez, size_t namez_len, char *match);
int namez_sort(char *namez, size_t namez_len);


