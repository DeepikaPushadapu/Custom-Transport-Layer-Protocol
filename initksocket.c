#include "ksocket.h"

int shmid_SM = -1;
int shmid_sock_info = -1;
KTPSocketEntry *SM = NULL;
SOCK_INFO *sock_info = NULL;
sem_t *Sem1 = NULL;
sem_t *Sem2 = NULL;
sem_t *SM_mutex = NULL;
int num_messages = 0;
int num_transmissions = 0;

typedef struct {
    int flag;
    time_t last_time;
    int ack_seq_no;
} Persistence_Timer_;

Persistence_Timer_ persistence_timer[MAX_KTP_SOCKETS];

void cleanup_on_exit() {
    if(num_messages>0){
        double avg_trans_per_msg = (double)(num_transmissions) / (num_messages);
        printf("\n==>> The average number of transmissions made to send each message (for p = %lf): %lf\n", P, avg_trans_per_msg);
    }
    else{
        printf("\n=> No message has been sent.\n");
    }

    if (SM != NULL) {
        if (shmdt(SM) == -1) {
            perror("shmdt(SM)");
        }
    }
    if (sock_info != NULL) {
        if (shmdt(sock_info) == -1) {
            perror("shmdt(sock_info)");
        }
    }

    if (Sem1 != NULL){
        sem_close(Sem1);
        sem_unlink("/Sem1");
    }
    if (Sem2 != NULL){ 
        sem_close(Sem2);
        sem_unlink("/Sem2");
    }
    if (SM_mutex != NULL) {
        sem_close(SM_mutex);
        sem_unlink("/SM_mutex");
    }

    if (shmid_SM != -1) {
        if (shmctl(shmid_SM, IPC_RMID, NULL) == -1) {
            perror("shmctl(IPC_RMID)");
        }
    }
    if (shmid_sock_info != -1) {
        if (shmctl(shmid_sock_info, IPC_RMID, NULL) == -1) {
            perror("shmctl(IPC_RMID)");
        }
    }

    printf("Shared memory and semaphores detached and destroyed successfully.\n");
}

void signal_handler(int signum) {
    if (signum == SIGINT)
        printf("\nReceived SIGINT. Detaching shared memory and quitting.\n");
    else if (signum == SIGQUIT)
        printf("\nReceived SIGQUIT. Detaching shared memory and quitting.\n");
    exit(EXIT_SUCCESS);
}

void *thread_R() {
    fd_set readfds;
    int max_sd, activity;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    Message msg;

    struct timeval timeout;
    timeout.tv_sec = T;
    timeout.tv_usec = 0;

    FD_ZERO(&readfds);
    if (sem_wait(SM_mutex) == -1) {
        perror("sem_wait");
        return NULL;
    }
    max_sd = -1;
    for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
        if(SM[i].socket_alloted){
            FD_SET(SM[i].udp_socket_id, &readfds);
            if (SM[i].udp_socket_id > max_sd) {
                max_sd = SM[i].udp_socket_id;
            }
        }
    }
    if (sem_post(SM_mutex) == -1) {
        perror("sem_post");
        return NULL;
    }
    
    while (1) {
        fd_set temp = readfds;

        activity = select(max_sd + 1, &temp, NULL, NULL, &timeout);

        if (activity < 0) {
            perror("select");
            if (sem_wait(SM_mutex) == -1) {
                perror("sem_wait");
                return NULL;
            }
            FD_ZERO(&readfds);
            max_sd = -1;
            for(int i=0; i<MAX_KTP_SOCKETS; i++){
                if(SM[i].socket_alloted){
                    FD_SET(SM[i].udp_socket_id, &readfds);
                    if (SM[i].udp_socket_id > max_sd) {
                        max_sd = SM[i].udp_socket_id;
                    }
                }
            }
            if (sem_post(SM_mutex) == -1) {
                perror("sem_post");
                return NULL;
            }
            continue;
        }

        if(activity == 0){
            timeout.tv_sec = T;
            timeout.tv_usec = 0;

            if (sem_wait(SM_mutex) == -1) {
                perror("sem_wait");
                return NULL;
            }
            FD_ZERO(&readfds);
            max_sd = -1;
            for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
                if(SM[i].socket_alloted){
                    
                    FD_SET(SM[i].udp_socket_id, &readfds);
                    if (SM[i].udp_socket_id > max_sd) {
                        max_sd = SM[i].udp_socket_id;
                    }
                    if(SM[i].recv_window.nospace==1 && SM[i].recv_window.window_size>0){
                        client_addr = SM[i].destination_addr;
                        Message ack_msg;
                        ack_msg.header.msg_type = 'A';
                        ack_msg.header.seq_no = (SM[i].recv_window.next_seq_no == 1) ? 255 : (SM[i].recv_window.next_seq_no - 1);
                        sprintf(ack_msg.msg, "%d", SM[i].recv_window.window_size);
                        sendto(SM[i].udp_socket_id, &ack_msg, sizeof(Message), 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
                        SM[i].recv_window.nospace = 0;
                    }
                }
            }
            if (sem_post(SM_mutex) == -1) {
                perror("sem_post");
                return NULL;
            }
            continue;
        }

        for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
            if(sem_wait(SM_mutex) == -1){
                perror("sem_wait");
                return NULL;
            }
            
            if (FD_ISSET(SM[i].udp_socket_id, &temp)) {
                ssize_t recv_len = recvfrom(SM[i].udp_socket_id, &msg, sizeof(Message), 0,
                                            (struct sockaddr *)&client_addr, &addr_len);
                if(SM[i].socket_alloted<=0){
                    FD_CLR(SM[i].udp_socket_id, &readfds);
                    sem_post(SM_mutex);
                    continue;
                }
                if (recv_len < 0) {
                    if(sem_post(SM_mutex)==-1){
                        perror("sem_post");
                        return NULL;
                    }
                    perror("recvfrom");
                    continue;
                }

                if(dropMessage(P)){
                    if(sem_post(SM_mutex)==-1){
                        perror("sem_post");
                        return NULL;
                    }
                    continue;
                }

                if(client_addr.sin_addr.s_addr != SM[i].destination_addr.sin_addr.s_addr || client_addr.sin_port != SM[i].destination_addr.sin_port){
                    if(sem_post(SM_mutex)==-1){
                        perror("sem_post");
                        return NULL;
                    }
                    continue;
                }

                if(msg.header.msg_type=='D'){   
                    if(msg.header.seq_no == SM[i].recv_window.next_seq_no && SM[i].recv_window.window_size>0){
                        int idx = SM[i].recv_window.index_to_write;
                        SM[i].recv_window.recv_buff[idx].ack_no = msg.header.seq_no;
                        memcpy(SM[i].recv_window.recv_buff[idx].message, msg.msg, MAX_MSG_SIZE);
                        SM[i].recv_window.window_size--;
                        if(SM[i].recv_window.window_size==0)SM[i].recv_window.nospace = 1;
                        int last_in_order = msg.header.seq_no;
                        int next_idx_to_write = SM[i].recv_window.index_to_write;
                        for(int k=1; k<RECEIVER_MSG_BUFFER; k++){
                            if(SM[i].recv_window.window_size==0)break;
                            int new_idx = (SM[i].recv_window.index_to_write+k)%RECEIVER_MSG_BUFFER;
                            if(SM[i].recv_window.recv_buff[new_idx].ack_no==-1){
                                break;
                            }
                            int next_exp_seq_no = (last_in_order == 255) ? 1 : (last_in_order + 1);
                            if (SM[i].recv_window.recv_buff[new_idx].ack_no != next_exp_seq_no)
                                break;
                            last_in_order = next_exp_seq_no;
                            next_idx_to_write = new_idx;
                            SM[i].recv_window.window_size--;
                            if(SM[i].recv_window.window_size==0)SM[i].recv_window.nospace = 1;
                        }
                        SM[i].recv_window.index_to_write = (next_idx_to_write + 1) % RECEIVER_MSG_BUFFER;
                        SM[i].recv_window.next_seq_no = (last_in_order == 255) ? 1 : (last_in_order + 1);

                        Message ack;
                        ack.header.msg_type = 'A';
                        ack.header.seq_no = last_in_order;
                        sprintf(ack.msg, "%d", SM[i].recv_window.window_size);
                        sendto(SM[i].udp_socket_id, &ack, sizeof(Message), 0, (struct sockaddr*)&client_addr, addr_len);

                        if(sem_post(SM_mutex)==-1){
                            perror("sem_post");
                            return NULL;
                        }
                        continue;
                    }
                    int inWindow = 0;
                    int expected_seq_no = SM[i].recv_window.next_seq_no;
                    int new_idx = -1;
                    for(int k=0; k<SM[i].recv_window.window_size; k++){
                        if(msg.header.seq_no==expected_seq_no){
                            new_idx = (SM[i].recv_window.index_to_write + k)%RECEIVER_MSG_BUFFER;
                            inWindow = 1;
                            break;
                        }
                        expected_seq_no = (expected_seq_no + 1) % 256;
                        if (expected_seq_no == 0)
                            expected_seq_no++;
                    }
                    if(inWindow){
                        if(SM[i].recv_window.recv_buff[new_idx].ack_no!=msg.header.seq_no){
                            SM[i].recv_window.recv_buff[new_idx].ack_no = msg.header.seq_no;
                            memcpy(SM[i].recv_window.recv_buff[new_idx].message, msg.msg, MAX_MSG_SIZE);
                        }
                        Message ack;
                        ack.header.msg_type = 'A';
                        ack.header.seq_no = (SM[i].recv_window.next_seq_no==1)? 15 : SM[i].recv_window.next_seq_no-1;
                        sprintf(ack.msg, "%d", SM[i].recv_window.window_size);
                        sendto(SM[i].udp_socket_id, &ack, sizeof(Message), 0, (struct sockaddr*)&client_addr, addr_len);

                        if(sem_post(SM_mutex)==-1){
                            perror("sem_post");
                            return NULL;
                        }
                        continue;
                    }
                    else{
                        Message ack;
                        ack.header.msg_type = 'A';
                        ack.header.seq_no = (SM[i].recv_window.next_seq_no==1)? 15 : SM[i].recv_window.next_seq_no-1;
                        sprintf(ack.msg, "%d", SM[i].recv_window.window_size);
                        sendto(SM[i].udp_socket_id, &ack, sizeof(Message), 0, (struct sockaddr*)&client_addr, addr_len);
                        
                        if(sem_post(SM_mutex)==-1){
                            perror("sem_post");
                            return NULL;
                        }
                        continue;
                    }
                }
                else if(msg.header.msg_type=='A'){
                    int idx = SM[i].send_window.window_start_index;
                    int ack_in_window = -1;
                    int len = -1;
                    for(int k = 0; k<SM[i].send_window.window_size; k++){
                        int new_idx = (idx+k)%SENDER_MSG_BUFFER;
                        if(SM[i].send_window.send_buff[new_idx].ack_no==-1)break;
                        if(SM[i].send_window.send_buff[new_idx].ack_no==msg.header.seq_no){
                            ack_in_window = new_idx;
                            len = k;
                            break;
                        }
                    }
                    if(ack_in_window!=-1){
                        for(int k = 0; k<=len; k++){
                            int new_idx = (idx+k)%SENDER_MSG_BUFFER;
                            SM[i].send_window.send_buff[new_idx].ack_no = -1;
                        }
                        SM[i].send_window.window_start_index = (ack_in_window+1)%SENDER_MSG_BUFFER;
                    }
                    SM[i].send_window.window_size = atoi(msg.msg);

                    if (SM[i].send_window.window_size>0){
                        persistence_timer[i].flag = 0;
                    }
                    if(SM[i].send_window.window_size==0){
                        if(persistence_timer[i].flag==0)persistence_timer[i].flag=1;
                        persistence_timer[i].last_time = time(NULL);
                        persistence_timer[i].ack_seq_no = msg.header.seq_no;
                    }

                    if(sem_post(SM_mutex)==-1){
                        perror("sem_post");
                        return NULL;
                    }
                    continue;
                }
                else if(msg.header.msg_type=='P'){
                    Message ack;
                    ack.header.msg_type = 'A';
                    ack.header.seq_no = msg.header.seq_no;
                    sprintf(ack.msg, "%d", SM[i].recv_window.window_size);
                    sendto(SM[i].udp_socket_id, &ack, sizeof(Message), 0, (struct sockaddr*)&client_addr, addr_len);
                    
                    if(sem_post(SM_mutex)==-1){
                        perror("sem_post");
                        return NULL;
                    }
                    continue;
                }

                if(sem_post(SM_mutex)==-1){
                    perror("sem_post");
                    return NULL;
                }
            }else{
                if(sem_post(SM_mutex)==-1){
                    perror("sem_post");
                    return NULL;
                }
            }
        }
    }

    return NULL;
}

void *thread_S() {
    time_t current_time;
    struct sockaddr_in addr;

    while (1) {
        usleep((T / 2) * 700000);

        if (sem_wait(SM_mutex) == -1) {
            perror("sem_wait");
            return NULL;
        }

        for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
            if (SM[i].socket_alloted) {
                if(persistence_timer[i].flag > 0){
                    int multiplier = (1 << (persistence_timer[i].flag - 1));
                    if(difftime(time(NULL), persistence_timer[i].last_time) >= multiplier * T){
                        Message probe_msg;
                        probe_msg.header.msg_type = 'P';
                        probe_msg.header.seq_no = persistence_timer[i].ack_seq_no;
                        addr = SM[i].destination_addr;
                        memset(probe_msg.msg, 0, sizeof(probe_msg.msg));
                        sendto(SM[i].udp_socket_id, &(probe_msg), sizeof(Message), 0, (struct sockaddr *)&addr, sizeof(addr));
                        persistence_timer[i].last_time = time(NULL);
                        if(persistence_timer[i].flag <= 3) persistence_timer[i].flag++;
                        continue;
                    }
                }
                for(int offset = 0; offset < SM[i].send_window.window_size; offset++){
                    int idx = (SM[i].send_window.window_start_index + offset) % SENDER_MSG_BUFFER;

                    if(SM[i].send_window.send_buff[idx].ack_no == -1) break;

                    if(SM[i].send_window.send_buff[idx].sent == 0){
                        addr = SM[i].destination_addr;
                        sendto(SM[i].udp_socket_id, &(SM[i].send_window.send_buff[idx].message), sizeof(Message), 0, (struct sockaddr *)&addr, sizeof(addr));
                        num_messages++;
                        num_transmissions++;
                        SM[i].send_window.send_buff[idx].time = time(NULL);
                        SM[i].send_window.send_buff[idx].sent = 1;
                        continue;
                    }
                    time(&current_time);
                    double time_gap = difftime(current_time, SM[i].send_window.send_buff[idx].time);
                    if(time_gap >= T){
                        addr = SM[i].destination_addr;
                        sendto(SM[i].udp_socket_id, &(SM[i].send_window.send_buff[idx].message), sizeof(Message), 0, (struct sockaddr *)&addr, sizeof(addr));
                        num_transmissions++;
                        SM[i].send_window.send_buff[idx].time = time(NULL);
                        continue;
                    }
                }
            }
        }

        if (sem_post(SM_mutex) == -1) {
            perror("sem_post");
            return NULL;
        }
    }

    return NULL;
}

void* thread_G(){
    while(1){
        sleep(3*T);
        
        if (sem_wait(SM_mutex) == -1) {
            perror("sem_wait");
            return NULL;
        }
        
        for(int i=0;i<MAX_KTP_SOCKETS;i++){
            if(SM[i].socket_alloted <= 0 ) continue;
            
            pid_t p=SM[i].process_id;
            if(kill(p,0)==0) continue;
            if(errno==ESRCH){
                close(SM[i].udp_socket_id);
                SM[i].socket_alloted = 0;
                printf("\n***************************\n");
                printf("-> Socket %d closed by the garbage collector thread\n", i);
                printf("***************************\n");
            }
        }
        if (sem_post(SM_mutex) == -1) {
            perror("sem_post");
            return NULL;
        }
    }
}

int main() {
    if (atexit(cleanup_on_exit) != 0) {
        perror("atexit");
        return EXIT_FAILURE;
    }

    key_t key_SM = ftok("ksocket.h", 'M');

    if ((shmid_SM = shmget(key_SM, MAX_KTP_SOCKETS * sizeof(KTPSocketEntry), IPC_CREAT | 0666)) < 0) {
        perror("shmget");
        exit(EXIT_FAILURE);
    }

    SM = (KTPSocketEntry *)shmat(shmid_SM, NULL, 0);
    if (SM == (KTPSocketEntry *)(-1)) {
        perror("shmat");
        exit(EXIT_FAILURE);
    }

    key_t key_sockinfo = ftok("ksocket.h", 'S');
    if ((shmid_sock_info = shmget(key_sockinfo, sizeof(SOCK_INFO), IPC_CREAT | 0666)) < 0) {
        perror("shmget");
        exit(EXIT_FAILURE);
    }

    sock_info = (SOCK_INFO *)shmat(shmid_sock_info, NULL, 0);
    if (sock_info == (SOCK_INFO *)(-1)) {
        perror("shmat");
        exit(EXIT_FAILURE);
    }

    if ((Sem1 = sem_open("/Sem1", O_CREAT, SEM_PERMS, 0)) == SEM_FAILED) {
        perror("sem_open");
        exit(EXIT_FAILURE);
    }

    if ((Sem2 = sem_open("/Sem2", O_CREAT, SEM_PERMS, 0)) == SEM_FAILED) {
        perror("sem_open");
        exit(EXIT_FAILURE);
    }

    if ((SM_mutex = sem_open("/SM_mutex", O_CREAT, SEM_PERMS, 1)) == SEM_FAILED) {
        perror("sem_open");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
        SM[i].socket_alloted = 0;
        SM[i].process_id = -1;
        SM[i].udp_socket_id = -1;
        memset(&(SM[i].destination_addr), 0, sizeof(struct sockaddr_in));
        memset(&(SM[i].send_window), 0, sizeof(swnd));
        memset(&(SM[i].recv_window), 0, sizeof(rwnd));
        SM[i].send_window.last_seq_no = 0;
        SM[i].send_window.window_size = 10;
        SM[i].send_window.window_start_index = 0;
        SM[i].recv_window.index_to_read = 0;
        SM[i].recv_window.next_seq_no = 1;
        SM[i].recv_window.window_size = 10;
        SM[i].recv_window.index_to_write = 0;
        SM[i].recv_window.nospace = 0;
        for(int j=0; j<SENDER_MSG_BUFFER; j++){
            SM[i].send_window.send_buff[j].ack_no = -1;
            SM[i].send_window.send_buff[j].sent = 0;
        }
        for(int j=0; j<RECEIVER_MSG_BUFFER; j++){
            SM[i].recv_window.recv_buff[j].ack_no = -1;
        }
    }
    memset(sock_info, 0, sizeof(SOCK_INFO));
    for(int i=0; i<MAX_KTP_SOCKETS; i++){
        persistence_timer[i].flag = 0;
    }

    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        perror("signal");
        exit(EXIT_FAILURE);
    }
    if (signal(SIGQUIT, signal_handler) == SIG_ERR) {
        perror("signal");
        exit(EXIT_FAILURE);
    }

    printf("Press Ctrl+C to detach shared memory and quit.\n");
    pthread_t thread_S_tid;
    if (pthread_create(&thread_S_tid, NULL, thread_S, NULL) != 0) {
        perror("pthread_create: Sender thread\n");
        exit(EXIT_FAILURE);
    }
    pthread_t thread_R_tid;
    if (pthread_create(&thread_R_tid, NULL, thread_R, NULL) != 0) {
        perror("pthread_create: Receiver thread\n");
        exit(EXIT_FAILURE);
    }
    pthread_t thread_G_tid;
    if (pthread_create(&thread_G_tid, NULL, thread_G, NULL) != 0) {
        perror("pthread_create: Garbage collector\n");
        exit(EXIT_FAILURE);
    }

    printf("\n***************************\n");
    printf("initksocket is initialized and running...\n");
    printf(" [Make sure to close all the user programs before closing this program] \n");
    printf("***************************\n");

    while (1) {
        if (sem_wait(Sem1) == -1) {
            perror("sem_wait");
            exit(EXIT_FAILURE);
        }

        if (sock_info->sock_id == 0 && sock_info->IP == 0 && sock_info->port == 0) {
            sock_info->sock_id = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock_info->sock_id == -1) {
                sock_info->errno_val = errno;
            }
            if (sem_post(Sem2) == -1) {
                perror("sem_post");
                exit(EXIT_FAILURE);
            }
        } else if (sock_info->sock_id != 0 && sock_info->port != 0) {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = sock_info->port;
            addr.sin_addr.s_addr = sock_info->IP;
            int ret = bind(sock_info->sock_id, (struct sockaddr *)&addr, sizeof(addr));
            if (ret == -1) {
                sock_info->errno_val = errno;
                sock_info->sock_id = -1;
            }
            if (sem_post(Sem2) == -1) {
                perror("sem_post");
                exit(EXIT_FAILURE);
            }
        } else if(sock_info->sock_id!=0 && sock_info->IP==0 && sock_info->port == 0){
            int status = close(sock_info->sock_id);
            if(status==-1){
                sock_info->sock_id = -1;
                sock_info->errno_val = errno;
            }
            if (sem_post(Sem2) == -1) {
                perror("sem_post");
                exit(EXIT_FAILURE);
            }
        }
    }

    return 0;
}