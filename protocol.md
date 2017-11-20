# Secure File Transfer Protocol

- To initiate a transfer, a client must connect to the server on the chosen port
- The client must send a header containing the initialization vector and metadata about the files the client wishes to transfer in the following format:

### Initial Header
| Description | Payload Size (bytes) |
|:------------|----:|
| Number of files being sent | 2 |
| Initialization vector | 16  |
| File 1 name  | 255 |
| File 1 encrypted size (bytes) | 4 |
| File 1 hash (sha-512)  | 64  |
| ... | ... |
| Repeat until n files |  |

- When at least one of the files the client wants to send is acceptable by the server, the servers responds with a transfer header that specifies the index of the file the client can send next (1 to n). The transfer header is in the following format:

### Server Response Header
| Description | Payload Size (bytes) |
|:------------|----:|
| Index of file to transfer | 2 |
| Pass/fail of last transfer | 1 |

Note: The pass/fail byte will be empty for the first file requested by the server. A pass will be encoded as 0x01, and fail will be encoded as 0x00.

- If the client has no key that exists on the server, the server will respond with a file index and pass/fail of 0 and closes the connection.

- If all of the file(s) the client attempts to send already exist on the server, the server will close the connection immediately.

- The client then sends the encrypted contents of the file requested by the server.

- After the file has been received by the server, the server will respond to the client with the end of transfer header until all non-duplicate files have been read. The server will close the connection when done receiving files.

### Server Directory Structure

The server maintains a directory structure starting in the directory the server is ran.

The server will maintain a directory called "keys", which contains files with client keys for decryption. The files are named using the clients "ip:port".

The server will store received files in a per-client directory. Each clients directory contains a sub directory for received files (maintaining the original filename), and a sub directory for hashes.

Example structure:

<pre>
rxer
│
│
│
└───received
│   │
│   │
│   │
│   └───127.0.0.2:6060
│   │   │
│   │   └───hashes
│   │   │   │   SHA512
│   │   │   │   SHA512
│   │   │
│   │   └───files
│   │       │   something1.txt
│   │       │   something2.txt
│   │
│   │
│   │
│   └───127.0.0.9:6060
│       │
│       └───hashes
│       │   │   SHA512
│       │   │   SHA512
│       │
│       └───files
│           │   rocktalk.txt
│           │   passwords.txt
│
│
│
└───keys
    │   127.0.0.2:6060
    │   127.0.0.9:6060
</pre>
