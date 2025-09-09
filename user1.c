#include "ksocket.h"   // Include the header file for MTP socket functions
#define BLOCK_SIZE 512 // Define the block size for reading and sending data

int main(int argc, char *argv[]) {
    // Check if command line arguments are provided for source IP, source port, destination IP, and destination port
    if (argc < 5) {
        printf("Please provide 'source IP, source port, destination IP, and destination port (respectively)' as command line arguments\n");
        exit(0);
    }

    // Variables to store source and destination IP addresses and ports
    char source_IP[INET_ADDRSTRLEN], dest_IP[INET_ADDRSTRLEN];
    strcpy(source_IP, argv[1]); // Copy source IP from command line argument
    strcpy(dest_IP, argv[3]); // Copy destination IP from command line argument
    unsigned short source_port = atoi(argv[2]); // Convert source port to unsigned short
    unsigned short dest_port = atoi(argv[4]); // Convert destination port to unsigned short

    // Create an KTP socket
    int sockfd = k_socket(AF_INET, SOCK_KTP, 0);
    if (sockfd < 0) {
        printf("Socket creation failed!\n");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to the specified source and destination IP addresses and ports
    int bind_status = k_bind(sockfd, inet_addr(source_IP), htons(source_port), inet_addr(dest_IP), htons(dest_port));
    if (bind_status < 0) {
        printf("Socket bind failed.\n");
        exit(EXIT_FAILURE);
    }

    // Set up the destination address structure
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(dest_IP);
    dest_addr.sin_port = htons(dest_port);

    // Open the file for reading
    int file_descriptor = open("content.txt", O_RDONLY);
    if (file_descriptor == -1) {
        printf("Error opening the file.\n");
        exit(EXIT_FAILURE);
    }

    char buff[BLOCK_SIZE]; // Buffer to read file contents
    ssize_t bytes_read, bytes_sent; // Variables to store the number of bytes read and sent

    // Send file contents in blocks of size 512 bytes/characters
    printf("User 1 (IP: %s, Port: %d) started sending the file contents.\n", source_IP, source_port);
    memset(buff, 0, sizeof(buff)); // Clear the buffer
    while ((bytes_read = read(file_descriptor, buff, BLOCK_SIZE - 1)) > 0) {
        // Send data block
        while ((bytes_sent = k_sendto(sockfd, buff, strlen(buff), 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr))) < 0) {
            if (errno == ENOBUFS) continue; // Retry if the error is due to lack of buffer space
            else {
                printf("Send failed from user 1\n");
                close(file_descriptor);
                exit(EXIT_FAILURE);
            }
        }
        memset(buff, 0, sizeof(buff)); // Clear the buffer
    }

    // Send termination block
    char termination_block[] = "\r\n.\r\n";
    while ((bytes_sent = k_sendto(sockfd, termination_block, strlen(termination_block), 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr))) < 0) {
        if (errno == ENOBUFS) continue; // Retry if the error is due to lack of buffer space
        else {
            printf("Send failed from user 1\n");
            close(file_descriptor);
            exit(EXIT_FAILURE);
        }
    }
    printf("User 1 (IP: %s, Port: %d) completed sending the file contents.\n", source_IP, source_port);

    close(file_descriptor); // Close the file descriptor

    // Wait indefinitely
    while (1);

    // Close the KTP socket
    //k_close(sockfd);

    return 0;
}