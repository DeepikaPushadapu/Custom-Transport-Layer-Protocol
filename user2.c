#include "ksocket.h"
#define BUFFER_SIZE 512

int main(int argc, char *argv[]){
    // Check if command-line arguments are provided
    if(argc < 5){
        printf("Please provide 'source IP, source port, destination IP, and destination port (respectively)' as command line arguments\n");
        exit(0);
    }

    // Extract command-line arguments
    char source_IP[INET_ADDRSTRLEN], dest_IP[INET_ADDRSTRLEN];
    strcpy(source_IP, argv[1]);
    strcpy(dest_IP, argv[3]);
    unsigned short source_port = atoi(argv[2]);
    unsigned short dest_port = atoi(argv[4]);

    // Create a socket
    int sockfd = k_socket(AF_INET, SOCK_KTP, 0);
    if(sockfd < 0){
        printf("Socket creation failed!\n");
        exit(EXIT_FAILURE);
    }

    // Bind the socket
    int bind_status = k_bind(sockfd, inet_addr(source_IP), htons(source_port), inet_addr(dest_IP), htons(dest_port));
    if(bind_status < 0){
        printf("Socket bind failed.\n");
        exit(EXIT_FAILURE);
    }

    // Prepare source address structure
    struct sockaddr_in src_addr;
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.sin_family = AF_INET;
    src_addr.sin_addr.s_addr = inet_addr(source_IP);
    src_addr.sin_port = htons(source_port);

    // Prepare destination address structure
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(dest_IP);
    dest_addr.sin_port = htons(dest_port);

    char buff[BUFFER_SIZE];
    int file_descriptor;
    ssize_t bytes_received;

    // Open or create file
    char filename[50];
    sprintf(filename, "recieved%s_%hu.txt", inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port));
    // sprintf(filename, "recieve.txt");

    file_descriptor = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (file_descriptor == -1) {
        printf("Error opening or creating the file.\n");
        exit(EXIT_FAILURE);
    }
    
    // Receive contents and write to file until termination block is received
    printf("User 2 (IP: %s, Port: %d) started receiving the file contents.\n", source_IP, source_port);
    
    while (1) {
        memset(buff, 0, sizeof(buff));
        int addrlen = sizeof(dest_addr);
        // Receive data
        while((bytes_received = k_recvfrom(sockfd, buff, sizeof(buff), 0, (struct sockaddr*)&dest_addr, (socklen_t *)&addrlen)) < 0){
            if(errno == ENOMSG)continue; // If no message is available yet, continue waiting
            else{
                printf("Receive failed for user 2\n");
                close(file_descriptor);
                exit(EXIT_FAILURE);
            }
        }

        // Check for termination block
        if (strcmp(buff, "\r\n.\r\n") == 0) {
            break; // Termination block received, exit loop
        }

        // Write received contents to file
        if (write(file_descriptor, buff, (strlen(buff) > BUFFER_SIZE ? BUFFER_SIZE : strlen(buff))) < 0) {
            printf("Error writing to the file.\n");
            close(file_descriptor);
            exit(EXIT_FAILURE);
        }
    }

    // Close the file
    close(file_descriptor);
    
    printf("User 2 (IP: %s, Port: %d) completed receiving the file contents (and is written back in file: %s).\n", source_IP, source_port, filename);

    //k_close(sockfd);

    return 0;
}