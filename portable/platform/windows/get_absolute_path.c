#include "platform_windows.h"

#include <io.h>
#include <search.h>
#include <stdio.h>

// convert relative path to absolute path
int get_absolute_path(char *absolute_path, const char *relative_path, size_t max)
{
	char *tmp_p;
	size_t len;

	// MSVC
	struct _finddatai64_t c_file;
	intptr_t handle;

	// This function replaces "/" to "\" automatically.
	if (_fullpath(absolute_path, relative_path, max) == NULL){
		perror("Failed to make absolute path");
		return 1;
	}

	// When the file exists, check each path component.
	handle = _findfirst64(absolute_path, &c_file);
	if (handle != (intptr_t) -1){
		_findclose(handle);

		// Even when case insensitive, use the original case for path component.
		len = strlen(c_file.name);
		tmp_p = strrchr(absolute_path, '\\');
		if (tmp_p != NULL){
			memcpy(tmp_p + 1, c_file.name, len);
		}

		// Check drive letter.
		tmp_p = absolute_path;
		if (tmp_p[1] == ':'){
			if ( (tmp_p[0] >= 'a') && (tmp_p[0] <= 'z') ){
				// Convert from lower case to upper case.
				tmp_p[0] -= 'a' - 'A';
			}
			tmp_p = strchr(tmp_p, '\\');
			if (tmp_p != NULL){
				tmp_p[0] = '/';
				tmp_p++;
			}
		}

		// Check each path component.
		tmp_p = strchr(tmp_p, '\\');
		while (tmp_p != NULL){
			tmp_p[0] = 0;

			//printf("find = %s\n", absolute_path);
			handle = _findfirst64(absolute_path, &c_file);
			if (handle != (intptr_t) -1){
				_findclose(handle);

				//printf("component = %s\n", c_file.name);
				len = strlen(c_file.name);
				memcpy(tmp_p - len, c_file.name, len);
			}

			// Replace directory mark from Windows OS style "\" to UNIX style "/" for compatibility.
			tmp_p[0] = '/';
			tmp_p = strchr(tmp_p + 1, '\\');
		}

	} else {
		// Even when the file doesn't exist, replace directory mark.
		tmp_p = absolute_path;
		tmp_p = strchr(tmp_p, '\\');
		while (tmp_p != NULL){
			tmp_p[0] = '/';
			tmp_p = strchr(tmp_p + 1, '\\');
		}
	}

	return 0;
}