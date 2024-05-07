#ifndef LIBROOT_PATHS_H
#define LIBROOT_PATHS_H

const char *libroot_get_root_prefix(void);
const char *libroot_get_jbroot_prefix(void);
const char *libroot_get_boot_uuid(void);
char *libroot_dyn_rootfspath(const char *path, char *resolvedPath);
char *libroot_dyn_jbrootpath(const char *path, char *resolvedPath);

#endif