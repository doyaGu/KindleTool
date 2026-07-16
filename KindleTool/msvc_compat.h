/* Native MSVC compatibility surface for KindleTool's POSIX-oriented source. */
#ifndef KINDLETOOL_MSVC_COMPAT_H
#define KINDLETOOL_MSVC_COMPAT_H

#include <BaseTsd.h>
#include <io.h>
#include <stddef.h>
#include <sys/stat.h>

#ifndef PATH_MAX
#	define PATH_MAX 4096
#endif
#ifndef PIPE_BUF
#	define PIPE_BUF 4096
#endif
#ifndef HOST_NAME_MAX
#	define HOST_NAME_MAX 256
#endif

typedef SSIZE_T ssize_t;

#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define strdup _strdup
#define fdopen _fdopen
#define fileno _fileno
#define unlink _unlink
#define close _close
#define access _access
#define fseeko _fseeki64
#define stat(...) kt_stat(__VA_ARGS__)
#define mkstemp kt_mkstemp
#define basename kt_basename

#ifndef R_OK
#	define R_OK 4
#endif
#ifndef W_OK
#	define W_OK 2
#endif
#ifndef X_OK
#	define X_OK 1
#endif
#ifndef S_ISDIR
#	define S_ISDIR(mode) (((mode) & _S_IFMT) == _S_IFDIR)
#endif
#ifndef restrict
#	define restrict __restrict
#endif
#ifndef __attribute__
#	define __attribute__(x)
#endif

struct option {
	const char* name;
	int has_arg;
	int* flag;
	int val;
};
enum { no_argument = 0, required_argument = 1, optional_argument = 2 };

extern char* optarg;
extern int optind;
extern int optopt;

int getopt_long(int argc, char* const argv[], const char* optstring, const struct option* longopts, int* longindex);
int kt_stat(const char* path, struct stat* result);
int kt_mkstemp(char* path_template);
const char* kt_basename(char* path);

#endif
