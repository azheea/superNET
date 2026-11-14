/*
 * C interface to the superNET core (crates/supernet-ffi), used by the iOS
 * Network Extension. Link libsupernet_ffi.a (built for aarch64-apple-ios).
 *
 * Order: supernet_prepare → supernet_mesh_address → (apply tunnel settings)
 *        → supernet_attach_tun → … → supernet_stop.
 * Strings returned here are freed with supernet_free_string.
 */
#ifndef SUPERNET_H
#define SUPERNET_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SupernetHandle SupernetHandle;

/* Start the engine and join the virtual network. NULL on failure. */
SupernetHandle *supernet_prepare(const char *profile_path, const char *data_dir);

/* "10.66.0.x/24", or "" when not in a virtual network. */
char *supernet_mesh_address(const SupernetHandle *h);

/* Hand over the tunnel's file descriptor (superNET owns it afterwards). 0 or -1. */
int supernet_attach_tun(SupernetHandle *h, int fd);

/* Engine and virtual-network status as JSON. */
char *supernet_status_json(const SupernetHandle *h);

/* The last error of h, or NULL. */
char *supernet_last_error(const SupernetHandle *h);

/* Stop everything; h is invalid afterwards. */
void supernet_stop(SupernetHandle *h);

void supernet_free_string(char *s);

#ifdef __cplusplus
}
#endif

#endif
