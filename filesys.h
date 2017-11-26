/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Interface to file system related functions
 */

#ifndef FILESYS_H
#define FILESYS_H

#include <stdbool.h>

#define DEFAULT_KEY_PATH ".key"
#define KEYS_DIR "keys"
#define KEYS_DIR_LEN 4
#define RECV_DIR "received"
#define HASHES_DIR "hashes"
#define FILES_DIR "files"

/*
 * Read a 256 bit key from a file at the specified path. Returns a key
 * if an expected length key is at the specified path. Returns NULL
 * otherwise
 */
uint8_t *read_key(char *key_path);

/*
 * Ensure the directory at the given path exists. Create the dir if
 * it doesn't exist. Returns true on success (exists or created),
 * false otherwise
 */
bool ensure_dir(char *path);

/*
 * Returns the directory name for a given address in ip:port form.
 * Returns NULL if the address structure is not IPv4 or IPv6
 */
char *addr_dirname(struct sockaddr_storage s);

/*
 * Return the size of a file in bytes at the given path. Will return
 * 0 if the path isn't a valid file
 */
uint32_t filesize(char *path);

/*
 * Concatenate two file paths. s2 is appended to s1
 */
char *concat_paths(char *s1, char *s2);

#endif
