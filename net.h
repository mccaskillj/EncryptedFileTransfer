/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Interface to networking related functions
 */

#ifndef NET_H
#define NET_H

/*
 * Write an entire source buffer to the destination socket
 */
void write_all(int dstfd, uint8_t *src, int src_len);

/*
 * Receive dst_len bytes from the source socket into destination
 * buffer. Returns 0 when the socket is closed, dst_len echoed
 * otherwise
 */
int recv_all(int srcfd, uint8_t *dst, int dst_len);

/*
 * Open a TCP socket that is connected to the specified
 * destination ip:port. Will bind to the provided local ip:port
 * if not NULL.
 */
int client_socket(char *svr_ip, char *svr_port, char *loc_ip, char *loc_port);

/*
 * Open a TCP socket that is ready to accept incoming
 * connections on the specified port
 */
int server_socket(char *port);

/*
 * Make the ip:port string for use in the file structure
 */
char *make_ip_port(struct sockaddr_storage *connection, socklen_t size);

#endif
