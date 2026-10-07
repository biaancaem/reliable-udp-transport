
#pragma once

#include <cstdint>
#include "utils.h"
#include <arpa/inet.h>
#include <map>
#include <vector>
#include <queue>
#include <set>

/* Maximum segment size, change as you see fit */
#define MAX_DATA_SIZE 512
#define MAX_SEGMENT_SIZE (MAX_DATA_SIZE + sizeof(poli_tcp_data_hdr))

#define MAX_CONNECTIONS 32
/* Protocol control block. Used track different parameters about a connection.
 * Will need to be extenden to solve the homework with other parameters such as
 * last_ack or status depending on how you implement your protocol. */

struct sender {
    uint16_t base_seq; //primul segment trimis dar inca neconfirmat
    uint16_t next_seq; // urmatorul numar de secventa folosit pentru un segment nou

    int max_window_seq; /* Used to store the max number of packets that can be inflight, since we can
                           have many more packets in our window inflight = trimise deja, dar inca neconfirmate prin ACK*/
    int spatiu_liber_receptor; //nr bytes liberi in receiver

    std::queue<std::vector<char>> buffer; // pt pachetele primite de la client
    int bytes_used; //cati bytes avem in buffer
    int buffer_cap; //capacitate maxima permisa pt bufferul senderului
    std::set<uint16_t> retransmise_deja;
    std::map<uint16_t, std::vector<char>> fereastra_glisanta_trimisa; //pt segmente trimise dar neconfirmate
};

struct receiver {
    uint16_t expected_seq; //primul nr de secventa lipsa
    uint16_t last_read_seq; //urmatorul segment care trebuie trimis

    int buffer_size; //dimensiune buffer
    int window_size; //dimensiunea ferestrei receiverului in nr de pachete

    int buffer_cap; // capacitate totala a bufferului receiverului
    int recv_buffer_used; //bytes utilizati din bufferul receiverului

    std::map<uint16_t, std::vector<char>> fereastra_glisanta_primita; //pt segmente primite de receiver
};

struct connection {
    /* common window for both the sender and receiver. */
    /* list window: A window representation */
    int sockfd; /* socket used for this connection */
    int conn_id; /* connection identifier */
    struct sockaddr_in servaddr; /* used to identify the destination */
    pthread_mutex_t con_lock; /* Used for syncronization with the handler thread and read/send calls.*/

    /* TODO. Parameters used only by the sender */
    struct sender sender;
    /* TODO. Parameters used only by the client */
    struct receiver receiver;
};

/* ########## API that we expose to the application ########### */

/* Equivalent of listen. Ran by the server to waits for a connection from a
 * client. Returns a connection id. Blocking untill it receives a connection
 * request */
int wait4connect(uint32_t ip, uint16_t port);
/* Equivalent of connect. Used by the client to connect to a server. */
int setup_connection(uint32_t ip, uint16_t port);
/* Equivalent to recv. Blocking if there is no data to be written in buffer */
int recv_data(int connectionid, char *buffer, int len);
/* Equivalent to send. Used by the client to send a stream of bytes as segments */
int send_data(int conn_id, char *buffer, int len);
/* Used to initialize your protocol on the receiver side. */
void init_receiver(int recv_buffer_bytes);
/* Used to initialize your protocol on the sender side */
void init_sender(int speed, int delay);

/* ######### Internal API used by sender and receiver ########### */
int recv_message_or_timeout(char *buff, size_t len, int *conn_id);
