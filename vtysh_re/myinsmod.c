#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Static module loader for the Beacon10 custom rootfs: no kmodloader needed.
 * usage: myinsmod <module-name | /path/to/module.ko>
 */
int main(int argc, char **argv)
{
	char buf[512];
	const char *path;

	if (argc < 2) {
		fprintf(stderr, "usage: myinsmod <name|path.ko>\n");
		return 2;
	}
	path = argv[1];
	if (path[0] != '/') {
		snprintf(buf, sizeof(buf), "/lib/modules/5.4.164/%s.ko", path);
		path = buf;
	}
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "myinsmod: open %s: %s\n", path, strerror(errno));
		return 1;
	}
	long rc = syscall(__NR_finit_module, fd, "", 0);
	if (rc != 0) {
		fprintf(stderr, "myinsmod: finit_module %s: %s (rc=%ld)\n", path, strerror(errno), rc);
		close(fd);
		return 1;
	}
	close(fd);
	fprintf(stderr, "myinsmod: loaded %s\n", path);
	return 0;
}
