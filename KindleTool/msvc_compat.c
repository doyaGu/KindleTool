/* Native MSVC implementations for KindleTool's small POSIX API surface. */
#include "msvc_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

char* optarg = NULL;
int optind = 1;
int optopt = 0;

static const char* short_option(const char* optstring, int option)
{
	for (const char* current = optstring; *current != '\0'; current++) {
		if (*current == option) return current;
	}
	return NULL;
}

int getopt_long(int argc, char* const argv[], const char* optstring, const struct option* longopts, int* longindex)
{
	const char* argument;
	const char* option;
	char* equals;

	optarg = NULL;
	if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0') return -1;
	if (strcmp(argv[optind], "--") == 0) { optind++; return -1; }
	argument = argv[optind];
	if (argument[1] == '-') {
		argument += 2;
		equals = strchr(argument, '=');
		for (int i = 0; longopts[i].name != NULL; i++) {
			size_t name_length = strlen(longopts[i].name);
			if (strncmp(argument, longopts[i].name, name_length) != 0 ||
			    (argument[name_length] != '\0' && argument[name_length] != '=')) continue;
			if (longindex != NULL) *longindex = i;
			if (longopts[i].has_arg == required_argument) {
				if (equals != NULL) optarg = equals + 1;
				else if (optind + 1 < argc) optarg = argv[++optind];
				else { optopt = longopts[i].val; optind++; return ':'; }
			} else if (longopts[i].has_arg == optional_argument && equals != NULL) {
				optarg = equals + 1;
			} else if (equals != NULL) {
				optopt = longopts[i].val; optind++; return '?';
			}
			optind++;
			if (longopts[i].flag != NULL) { *longopts[i].flag = longopts[i].val; return 0; }
			return longopts[i].val;
		}
		optind++;
		return '?';
	}

	option = short_option(optstring, argument[1]);
	if (option == NULL || argument[2] != '\0') { optopt = (unsigned char) argument[1]; optind++; return '?'; }
	if (option[1] == ':') {
		if (optind + 1 >= argc) { optopt = (unsigned char) argument[1]; optind++; return ':'; }
		optarg = argv[++optind];
	}
	optind++;
	return (unsigned char) argument[1];
}

int kt_mkstemp(char* path_template)
{
	static const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	size_t length;
	if (path_template == NULL || (length = strlen(path_template)) < 6 || strcmp(path_template + length - 6, "XXXXXX") != 0) {
		errno = EINVAL;
		return -1;
	}
	for (unsigned int attempt = 0; attempt < 256; attempt++) {
		for (size_t i = length - 6; i < length; i++) path_template[i] = alphabet[(unsigned int) rand() % (sizeof(alphabet) - 1)];
		int fd = _open(path_template, _O_RDWR | _O_CREAT | _O_EXCL | _O_BINARY, _S_IREAD | _S_IWRITE);
		if (fd >= 0 || errno != EEXIST) return fd;
	}
	errno = EEXIST;
	return -1;
}

int kt_stat(const char* path, struct stat* result)
{
	struct _stat64 native_stat;
	if (_stat64(path, &native_stat) != 0) return -1;
	memset(result, 0, sizeof(*result));
	result->st_dev = native_stat.st_dev;
	result->st_ino = native_stat.st_ino;
	result->st_mode = native_stat.st_mode;
	result->st_nlink = native_stat.st_nlink;
	result->st_uid = native_stat.st_uid;
	result->st_gid = native_stat.st_gid;
	result->st_rdev = native_stat.st_rdev;
	result->st_size = native_stat.st_size;
	result->st_atime = native_stat.st_atime;
	result->st_mtime = native_stat.st_mtime;
	result->st_ctime = native_stat.st_ctime;
	return 0;
}

const char* kt_basename(char* path)
{
	const char* result = path;
	if (path == NULL) return "";
	for (const char* current = path; *current != '\0'; current++) if (*current == '/' || *current == '\\') result = current + 1;
	return result;
}
