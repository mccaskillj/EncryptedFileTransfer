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
int write_all(int dst, char *src, int src_len);

int recv_all(int socketfd, char *buf, int size);

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

#endif
