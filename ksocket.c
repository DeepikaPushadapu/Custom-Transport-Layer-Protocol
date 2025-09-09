#include "ksocket.h"

// Function to randomly drop a message based on probability p
int dropMessage(float p) {
    float rand_val = (float)rand() / RAND_MAX; // Generate a random value between 0 and 1

    if (rand_val < p) {
        printf("Message dropped!\n");
        return 1; // Return true, message dropped
    } else {
        printf("message received\n");
        return 0; // Return false, message not dropped
    }
}

// Function to clean up resources
void cleanup(KTPSocketEntry *SM, SOCK_INFO *sock_info, sem_t *Sem1, sem_t *Sem2, sem_t *SM_mutex){
    if (SM != NULL) shmdt(SM); // Detach shared memory segment for SM
    if (sock_info != NULL) shmdt(sock_info); // Detach shared memory segment for sock_info
    if (Sem1 != NULL) sem_close(Sem1); // Close semaphore Sem1
    if (Sem2 != NULL) sem_close(Sem2); // Close semaphore Sem2
    if (SM_mutex != NULL) sem_close(SM_mutex); // Close semaphore SM_mutex
}

// Function to open an KTP socket
int k_socket(int domain, int type, int protocol) {
    // Check if the domain is AF_INET or PF_INET, type is SOCK_KTP, and protocol is 0
    if ((!(domain == AF_INET || domain == PF_INET)) || type != SOCK_KTP || protocol != 0) {
        // Set errno based on the error condition
        if (type != SOCK_KTP)
            errno = EPROTOTYPE;
        else if (protocol != 0)
            errno = EPROTONOSUPPORT;
        else
            errno = EAFNOSUPPORT;
        return -1;
    }

    // Declare variables for shared memory, semaphores, and socket information
    int shm_id;
    KTPSocketEntry *SM = NULL;
    SOCK_INFO *sock_info = NULL;
    sem_t *Sem1 = NULL;
    sem_t *Sem2 = NULL;
    sem_t *SM_mutex = NULL;

    // Create key for shared memory SM table
    key_t key_SM = ftok("ksocket.h", 'M');
    // Get shared memory segment for SM table
    if ((shm_id = shmget(key_SM, MAX_KTP_SOCKETS * sizeof(KTPSocketEntry), 0666)) < 0) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        perror(" error in shmget at SM in k_socket");
        return -1;
    }
    // Attach shared memory segment for SM table
    SM = (KTPSocketEntry *)shmat(shm_id, NULL, 0);
    if (SM == (KTPSocketEntry *)(-1)) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        perror(" error in shmat at SM in k_socket");
        return -1;
    }

    // Create key for shared memory SOCK_INFO
    key_t key_sockinfo = ftok("ksocket.h", 'S');
    // Get shared memory segment for SOCK_INFO
    if ((shm_id = shmget(key_sockinfo, sizeof(SOCK_INFO), 0666)) < 0) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }
    // Attach shared memory segment for SOCK_INFO
    sock_info = (SOCK_INFO *)shmat(shm_id, NULL, 0);
    if (sock_info == (SOCK_INFO *)(-1)) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        perror("shmat");
        return -1;
    }

    // Open semaphore Sem1
    Sem1 = sem_open("/Sem1", 0);
    if (Sem1 == SEM_FAILED) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }
    // Open semaphore Sem2
    Sem2 = sem_open("/Sem2", 0);
    if (Sem2 == SEM_FAILED) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }

    // Open semaphore SM_mutex
    if ((SM_mutex = sem_open("/SM_mutex", 0)) == SEM_FAILED) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }

    // Find a free entry in the shared memory
    int free_entry_index = -1;
    if (sem_wait(SM_mutex) == -1) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }
    for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
        if (SM[i].socket_alloted == 0) {
            free_entry_index = i;
            break;
        }
    }
    if (sem_post(SM_mutex) == -1) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }

    // Check if free entry available
    if (free_entry_index == -1) {
        // No free entry available, set errno and return
        errno = ENOBUFS;
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }

    // Signal Sem1
    if (sem_post(Sem1) == -1) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }

    // Wait on Sem2
    if (sem_wait(Sem2) == -1) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }

    // Check SOCK_INFO for errors
    if (sock_info->sock_id == -1) {
        errno = sock_info->errno_val;
        free_entry_index = -1;
    } else {
        // Update SM table with socket information
        if (sem_wait(SM_mutex) == -1) {
            cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
            return -1;
        }
        SM[free_entry_index].socket_alloted = 1;
        SM[free_entry_index].process_id = getpid();
        SM[free_entry_index].udp_socket_id = sock_info->sock_id;
        memset(&(SM[free_entry_index].destination_addr), 0, sizeof(struct sockaddr_in));
        memset(&(SM[free_entry_index].recv_window), 0, sizeof(rwnd));
        memset(&(SM[free_entry_index].send_window), 0, sizeof(swnd));
        SM[free_entry_index].send_window.last_seq_no = 0;
        SM[free_entry_index].send_window.window_size = 5;
        SM[free_entry_index].send_window.window_start_index = 0;
        SM[free_entry_index].recv_window.index_to_read = 0;
        SM[free_entry_index].recv_window.next_seq_no = 1;
        SM[free_entry_index].recv_window.window_size = 5;
        SM[free_entry_index].recv_window.index_to_write = 0;
        SM[free_entry_index].recv_window.nospace = 0;
        for (int j = 0; j < SENDER_MSG_BUFFER; j++) {
            SM[free_entry_index].send_window.send_buff[j].ack_no = -1;
            SM[free_entry_index].send_window.send_buff[j].sent = 0;
        }
        for (int j = 0; j < RECEIVER_MSG_BUFFER; j++) {
            SM[free_entry_index].recv_window.recv_buff[j].ack_no = -1;
        }
        if (sem_post(SM_mutex) == -1) {
            cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
            return -1;
        }
    }

    // Reset SOCK_INFO
    memset(sock_info, 0, sizeof(SOCK_INFO));

    // Cleanup resources
    cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);

    // Return the corresponding index in the SM table as the required socket number
    return free_entry_index;
}

// Function to bind an KTP socket
int k_bind(int sockfd, unsigned long src_ip, unsigned short src_port, unsigned long dest_ip, unsigned short dest_port) {
    // Declare variables for shared memory, semaphores, and socket information
    int shm_id;
    KTPSocketEntry *SM = NULL;
    SOCK_INFO *sock_info = NULL;
    sem_t *Sem1 = NULL;
    sem_t *Sem2 = NULL;
    sem_t *SM_mutex = NULL;

    // Create key for shared memory SM table
    key_t key_SM = ftok("ksocket.h", 'M');
    // Get shared memory segment for SM table
    if ((shm_id = shmget(key_SM, MAX_KTP_SOCKETS * sizeof(KTPSocketEntry), 0666)) < 0) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }
    // Attach shared memory segment for SM table
    SM = (KTPSocketEntry *)shmat(shm_id, NULL, 0);
    if (SM == (KTPSocketEntry *)(-1)) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        perror("shmat");
        return -1;
    }

    // Create key for shared memory SOCK_INFO
    key_t key_sockinfo = ftok("ksocket.h", 'S');
    // Get shared memory segment for SOCK_INFO
    if ((shm_id = shmget(key_sockinfo, sizeof(SOCK_INFO), 0666)) < 0) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }
    // Attach shared memory segment for SOCK_INFO
    sock_info = (SOCK_INFO *)shmat(shm_id, NULL, 0);
    if (sock_info == (SOCK_INFO *)(-1)) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        perror("shmat");
        return -1;
    }

    // Open semaphore Sem1
    Sem1 = sem_open("/Sem1", 0);
    if (Sem1 == SEM_FAILED) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }
    // Open semaphore Sem2
    Sem2 = sem_open("/Sem2", 0);
    if (Sem2 == SEM_FAILED) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }
    // Open semaphore SM_mutex
    if ((SM_mutex = sem_open("/SM_mutex", 0)) == SEM_FAILED) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }

    // Acquire SM_mutex before accessing shared memory
    if (sem_wait(SM_mutex) == -1) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }
    if(SM[sockfd].process_id != getpid()){
        // Error if this socket was created by some other process
        errno = EBADF;
        sem_post(SM_mutex);
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }
    // Release SM_mutex after accessing shared memory
    if (sem_post(SM_mutex) == -1) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }

    // Set SOCK_INFO fields
    sock_info->sock_id = SM[sockfd].udp_socket_id;
    sock_info->IP = src_ip;
    sock_info->port = src_port;

    // Signal Sem1
    if (sem_post(Sem1) == -1) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }

    // Wait on Sem2
    if (sem_wait(Sem2) == -1) {
        cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
        return -1;
    }

    int success = 0;
    // Check SOCK_INFO for errors
    if (sock_info->sock_id == -1) {
        errno = sock_info->errno_val;
        success = -1;
    } else {
        // Update SM table with destination address
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = dest_port;
        dest_addr.sin_addr.s_addr = dest_ip;
        // Acquire SM_mutex before updating shared memory
        if (sem_wait(SM_mutex) == -1) {
            cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
            return -1;
        }
        SM[sockfd].destination_addr = dest_addr;
        // Release SM_mutex after updating shared memory
        if (sem_post(SM_mutex) == -1) {
            cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);
            return -1;
        }
    }

    // Reset SOCK_INFO
    memset(sock_info, 0, sizeof(SOCK_INFO));

    // Cleanup resources
    cleanup(SM, sock_info, Sem1, Sem2, SM_mutex);

    return success;
}

// Function to send data over an KTP socket
ssize_t k_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_address, socklen_t addrlen){
    // Casting destination address to sockaddr_in
    struct sockaddr_in *dest_addr = (struct sockaddr_in *)dest_address;

    // Declare variables for shared memory and mutex
    KTPSocketEntry *SM = NULL;
    sem_t *SM_mutex = NULL;

    // Get shared memory segment for KTPSocketEntry
    key_t key_SM = ftok("ksocket.h", 'M');
    int shm_id = shmget(key_SM, MAX_KTP_SOCKETS * sizeof(KTPSocketEntry), 0666);
    if (shm_id == -1) {
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        return -1;
    }
    SM = (KTPSocketEntry *)shmat(shm_id, NULL, 0);
    if (SM == (KTPSocketEntry *)(-1)) {
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        perror("shmat");
        return -1;
    }

    // Open mutex
    if ((SM_mutex = sem_open("/SM_mutex", 0)) == SEM_FAILED) {
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        return -1;
    }

    // Acquire mutex lock
    if (sem_wait(SM_mutex) == -1) {
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        return -1;
    }

    // Check if socket descriptor is valid and belongs to the current process
    if (sockfd < 0 || sockfd >= MAX_KTP_SOCKETS || SM[sockfd].socket_alloted == 0 || SM[sockfd].process_id != getpid()) {
        errno = EBADF; // Bad file descriptor
        sem_post(SM_mutex); // Release the lock
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        return -1;
    }

    // Check if the destination address matches the bound address
    if (!(dest_addr->sin_addr.s_addr == SM[sockfd].destination_addr.sin_addr.s_addr &&
          dest_addr->sin_port == SM[sockfd].destination_addr.sin_port)) {
        errno = ENOTCONN;
        sem_post(SM_mutex); // Release the lock
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        return -1;
    }

    // Find a free index in the sender message buffer
    int free_index = -1;
    int idx = SM[sockfd].send_window.window_start_index;
    for (int i = 0; i < SENDER_MSG_BUFFER; i++) {
        int new_idx = (idx + i) % SENDER_MSG_BUFFER;
        if (SM[sockfd].send_window.send_buff[new_idx].ack_no == -1) {
            free_index = new_idx;
            break;
        }
    }

    // If no free index is found, return error
    if (free_index == -1) {
        errno = ENOBUFS;
        sem_post(SM_mutex);
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        return -1;
    }

    // Update sender window information and copy message data
    SM[sockfd].send_window.last_seq_no = (SM[sockfd].send_window.last_seq_no + 1) % 256;
    if (SM[sockfd].send_window.last_seq_no == 0)
        SM[sockfd].send_window.last_seq_no++;

    SM[sockfd].send_window.send_buff[free_index].ack_no = SM[sockfd].send_window.last_seq_no;
    SM[sockfd].send_window.send_buff[free_index].time = time(NULL);
    memset(&(SM[sockfd].send_window.send_buff[free_index].message), 0, sizeof(Message));
    SM[sockfd].send_window.send_buff[free_index].message.header.msg_type = 'D';
    SM[sockfd].send_window.send_buff[free_index].message.header.seq_no = SM[sockfd].send_window.last_seq_no;
    memcpy(SM[sockfd].send_window.send_buff[free_index].message.msg, buf, len);
    SM[sockfd].send_window.send_buff[free_index].sent = 0;

    // Release mutex lock
    if (sem_post(SM_mutex) == -1) {
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        return -1;
    }

    // Cleanup resources
    cleanup(SM, NULL, NULL, NULL, SM_mutex);

    return len;
}

// Function to receive data from an KTP socket
ssize_t k_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    // Declare variables for shared memory and semaphore
    KTPSocketEntry *SM = NULL;
    sem_t *SM_mutex = NULL;

    // Get shared memory segment for SM table
    key_t key_SM = ftok("ksocket.h", 'M');
    int shm_id = shmget(key_SM, MAX_KTP_SOCKETS * sizeof(KTPSocketEntry), 0666);
    if (shm_id == -1) {
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        perror("shmget");
        return -1;
    }
    SM = (KTPSocketEntry *)shmat(shm_id, NULL, 0);
    if (SM == (KTPSocketEntry *)(-1)) {
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        perror("shmat");
        return -1;
    }

    // Open semaphore SM_mutex
    if ((SM_mutex = sem_open("/SM_mutex", 0)) == SEM_FAILED) {
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        perror("sem_open");
        return -1;
    }

    // Acquire lock
    if (sem_wait(SM_mutex) == -1) {
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        return -1;
    }

    // Check validity of sockfd
    if (sockfd < 0 || sockfd >= MAX_KTP_SOCKETS || SM[sockfd].socket_alloted == 0 || SM[sockfd].process_id != getpid()) {
        errno = EBADF; // Bad file descriptor
        sem_post(SM_mutex); // Release the lock
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        return -1;
    }

    int idx = SM[sockfd].recv_window.index_to_read;

    // Check if there's a message available in the receive buffer
    if (SM[sockfd].recv_window.recv_buff[idx].ack_no == -1) {
        errno = ENOMSG; // No message available
        sem_post(SM_mutex); // Release the lock
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        return -1;
    }

    // Copy the message to the buffer
    size_t copy_len = len < MAX_MSG_SIZE ? len : MAX_MSG_SIZE;
    memcpy(buf, SM[sockfd].recv_window.recv_buff[idx].message, copy_len);

    // Update source address if provided
    if (src_addr != NULL) {
        memcpy(src_addr, &(SM[sockfd].destination_addr), sizeof(struct sockaddr_in));
    }

    // Update addrlen if provided
    if (addrlen != NULL) {
        *addrlen = sizeof(struct sockaddr_in);
    }

    // Update next sequence number and window size
    SM[sockfd].recv_window.recv_buff[idx].ack_no = -1;
    memset(&(SM[sockfd].recv_window.recv_buff[idx].message), 0, sizeof(SM[sockfd].recv_window.recv_buff[idx].message));
    SM[sockfd].recv_window.index_to_read = (idx + 1) % RECEIVER_MSG_BUFFER;
    SM[sockfd].recv_window.window_size++;

    // Release the lock
    if (sem_post(SM_mutex) == -1) {
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        return -1;
    }

    // Cleanup resources
    cleanup(SM, NULL, NULL, NULL, SM_mutex);

    // Return the length of the copied message
    return copy_len;
}

// Function to close an KTP socket
int k_close(int sockfd) {
    KTPSocketEntry *SM = NULL; // Pointer to the shared memory KTPSocketEntry
    sem_t *SM_mutex = NULL; // Semaphore for mutual exclusion

    int shm_id;
    // Get the shared memory segment for KTPSocketEntry
    key_t key_SM = ftok("ksocket.h", 'M');
    if ((shm_id = shmget(key_SM, MAX_KTP_SOCKETS * sizeof(KTPSocketEntry), 0666)) < 0) {
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        return -1;
    }
    // Attach the shared memory segment
    SM = (KTPSocketEntry *)shmat(shm_id, NULL, 0);
    if (SM == (KTPSocketEntry *)(-1)) {
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        return -1;
    }

    // Open the semaphore for mutual exclusion
    if ((SM_mutex = sem_open("/SM_mutex", 0)) == SEM_FAILED) {
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        return -1;
    }

    // Lock the shared memory for mutual exclusion
    if (sem_wait(SM_mutex) == -1) {
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        return -1;
    }

    // Check if the socket is allocated and belongs to the current process
    if (sockfd < 0 || sockfd >= MAX_KTP_SOCKETS || SM[sockfd].socket_alloted == 0 || SM[sockfd].process_id != getpid()) {
        errno = EBADF; // Set errno to indicate bad file descriptor
        sem_post(SM_mutex); // Release the lock
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        return -1;
    }

    // Mark the socket entry as free
    SM[sockfd].socket_alloted = 0;

    // Unlock the shared memory
    if (sem_post(SM_mutex) == -1) {
        cleanup(SM, NULL, NULL, NULL, SM_mutex);
        return -1;
    }

    // Cleanup resources
    cleanup(SM, NULL, NULL, NULL, SM_mutex);

    return 0; // Return success
}
