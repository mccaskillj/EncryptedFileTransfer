/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Interface to file system related functions
 */

#ifndef FILESYS_H
#define FILESYS_H

#define DEFAULT_KEY_PATH ".key"

/*
 * Read a 256 bit key from a file at the specified path. Returns a key
 * if an expected length key is at the specified path. Returns NULL
 * otherwise
 */
char *read_key(char *key_path);

/*
 * Ensure the directory at the given path exists. Create the dir if
 * it doesn't exist. Returns true on success (exists or created),
 * false otherwise
 */
void ensure_dir(char *path);

/*
 * Returns the directory name for a given address in ip:port form.
 * Returns NULL if the address structure is not IPv4 or IPv6
 */
char *addr_dirname(struct sockaddr_storage s);

#endif
