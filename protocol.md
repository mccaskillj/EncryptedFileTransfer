# Secure File Transfer Protocol

- To initiate a transfer, a client must connect to the server on the chosen port
- The client must send a header containing the initialization vector and metadata about the files the client wishes to transfer in the following format:

### Initial Header
| Description | Payload Size (bytes) |
|:------------|----:|
| Number of files being sent | 2 |
| Initialization vector | 32  |
| File 1 name  | 255 |
| File 1 encrypted size (bytes) | 4 |
| File 1 hash (sha-512)  | 64  |
| ... | ... |
| Repeat until n files |  |

- If the client has no key that exists on the server, the server will respond with a SYN byte (0x16), and close the connection.

- When the server receives the header, the server will check to see if any duplicate files with the same hash exist. If all of the file(s) the client attempts to send already exist on the server, the server will respond with a NAK byte (0x15), and close the connection.

- When at least one of the files the client wants to send is acceptable by the server, the servers responds with a transfer header that specifies the index of the file the client can send next (1 to n). The transfer header is in the following format:


### Transfer Header
| Description | Payload Size (bytes) |
|:------------|----:|
| Index of file to transfer | 2 |
| Pass/fail of last transfer | 1 |

Note: The pass/fail byte will be empty for the first file requested by the server.

- The client then sends the encrypted contents of the file requested by the server.

- After the file has been received by the server, the server will respond to the client with the end of transfer header until all non-duplicate files have been read. The server will close the connection when done receiving files.

