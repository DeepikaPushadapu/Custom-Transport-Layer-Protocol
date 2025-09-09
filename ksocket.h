#ifndef KSOCKET_H
#define KSOCKET_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/shm.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define SEM_PERMS (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)


#define SOCK_KTP 100


#define T 5

// Probability with which a message will be dropped
#define P 0.5

// Define the maximum number of active KTP sockets
#define MAX_KTP_SOCKETS 10

// Define the maximum message size
#define MAX_MSG_SIZE 512

// Define the size of the sender message buffer
#define SENDER_MSG_BUFFER 10

// Define the size of the receiver message buffer
#define RECEIVER_MSG_BUFFER 10

// Define the structure for a message header
typedef struct {
    char msg_type;    // 'D' for data, 'A' for acknowledgment, 'P' for Probe
    int seq_no;       // Sequence number of the message
} MessageHeader;

// Define the structure for a complete message
typedef struct {
    MessageHeader header;   // Message header
    char msg[MAX_MSG_SIZE]; // Message body
} Message;

// Define the structure for a message to be sent
typedef struct {
    int ack_no;         // If the acknowledgment for the message is received, it's -1; else it's equal to the sequence number of the message
    time_t time;        // Time of sending
    int sent;           // Flag indicating if the message has been sent once
    Message message;    // Actual message to be sent
} send_msg;

// Define the structure for a received message
typedef struct {
    int ack_no;             // Acknowledgment number
    char message[MAX_MSG_SIZE]; // Message body
} recv_msg;

// Define the structure for the sender's window
typedef struct {
    int window_size;            // Size of the window
    int window_start_index;     // Index of the starting point of the window
    int last_seq_no;            // Last sequence number used in the window
    send_msg send_buff[SENDER_MSG_BUFFER]; // Buffer for messages to be sent
} swnd;

// Define the structure for the receiver's window
typedef struct {
    int window_size;            // Size of the window
    int index_to_read;          // Index to read the next message from
    int next_seq_no;            // Next expected sequence number
    int index_to_write;         // Index to write the next received message to
    int nospace;                // Flag indicating if there's no space in the buffer
    recv_msg recv_buff[RECEIVER_MSG_BUFFER]; // Buffer for received messages
} rwnd;

// Define the structure for an KTP socket entry in shared memory
typedef struct {
    int socket_alloted;             // Flag to check whether the slot has been allotted
    pid_t process_id;               // Process ID
    int udp_socket_id;              // UDP socket ID
    struct sockaddr_in destination_addr; // Destination address
    swnd send_window;               // Sender's window
    rwnd recv_window;               // Receiver's window
} KTPSocketEntry;

// Structure to hold socket creation and binding information
typedef struct {
    int sock_id;                // Socket ID
    unsigned long IP;           // IP address
    unsigned short port;        // Port number
    int errno_val;              // Error number value
} SOCK_INFO;

// Function to open an KTP socket
int k_socket(int domain, int type, int protocol);

// Function to bind an KTP socket
int k_bind(int sockfd, unsigned long src_ip, unsigned short src_port, unsigned long dest_ip, unsigned short dest_port);

// Function to send data over an KTP socket
ssize_t k_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);

// Function to receive data frok an KTP socket
ssize_t k_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

// Function to close an KTP socket
int k_close(int sockfd);

// Function to drop a message based on probability p
int dropMessage(float p);

#endif 
