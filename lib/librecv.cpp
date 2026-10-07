#include <pthread.h>
#include <cstdlib>
#include <map>
#include <cstdint>
#include "lib.h"
#include "utils.h"
#include "protocol.h"
#include <poll.h>
#include <cassert>
#include <sys/timerfd.h>
#include <string.h>
#include <unistd.h>
#include <vector>

using namespace std;

std::map<int, struct connection *> cons;

struct pollfd data_fds[MAX_CONNECTIONS];
/* Used for timers per connection */
struct pollfd timer_fds[MAX_CONNECTIONS];
int fdmax = 0;
int listenfd;
int tmp_buffer_bytes = 0; // dimensiunea bufferului pana se creeaza conexiunea

void send_ctrl_packet(struct connection *con, uint8_t packet_type, uint16_t seq_num)
{
    struct poli_tcp_ctrl_hdr reply;
    memset(&reply, 0, sizeof(struct poli_tcp_ctrl_hdr));

    // Campuri universale, identice pentru orice pachet de control
    reply.protocol_id = POLI_PROTOCOL_ID;
    reply.conn_id = con->conn_id;
    reply.type = packet_type;                     //  ACK, SYN, sau SYN_ACK
    reply.ack_num = htons(seq_num);               // nr de secventa primit ca parametru

    // Calculam si limitam fereastra libera
    int fereastra_libera = con->receiver.buffer_cap - con->receiver.recv_buffer_used;
    if (fereastra_libera < 0) {
        fereastra_libera = 0;
    }
    if (fereastra_libera > 65535) {
        fereastra_libera = 65535;
    }
    reply.recv_window = htons((uint16_t)fereastra_libera);

    // Trimitere pe socket
    int rc = sendto(con->sockfd, &reply, sizeof(reply), 0,
                    (struct sockaddr *)&(con->servaddr), sizeof(con->servaddr));
    assert(rc >= 0);
}

// Scade octetii cititi din bufferul ocupat si garanteaza ca rezultatul nu devine negativ
int actualizeaza_spatiu_buffer(int octeti_ocupati, int octeti_cititi)
{
    int rezultat = octeti_ocupati - octeti_cititi;
    if (rezultat < 0) {
        return 0;
    }
    return rezultat;
}

int recv_data(int conn_id, char *buffer, int len)
{
    int size = 0;
    pthread_mutex_lock(&cons[conn_id]->con_lock);

    /* We will write code here as to not have sync problems with recv_handler */
    struct connection *con = cons[conn_id];
    while (con->receiver.fereastra_glisanta_primita.count(con->receiver.last_read_seq) == 0) {
        pthread_mutex_unlock(&cons[conn_id]->con_lock);
        usleep(1000);//
        pthread_mutex_lock(&cons[conn_id]->con_lock);
    }
    std::map<uint16_t, std::vector<char>> &fereastra = con->receiver.fereastra_glisanta_primita;
    while (size < len && fereastra.count(con->receiver.last_read_seq) != 0) {
        // Luam referinta catre vectorul de caractere (payload-ul pachetului curent)
        std::vector<char> &pachet_curent = fereastra[con->receiver.last_read_seq];
        //spatiu ramas in buffer = len - size;
        int dimensiune_pachet = pachet_curent.size();
        //pachetul ramas incape tot in buffer
        if (dimensiune_pachet <= len - size) {
            memcpy(buffer + size, pachet_curent.data(), dimensiune_pachet);
            size = size + dimensiune_pachet;
            con->receiver.recv_buffer_used = actualizeaza_spatiu_buffer(con->receiver.recv_buffer_used, dimensiune_pachet);
            //stergem pachetul din map si trecem la urm index
            fereastra.erase(con->receiver.last_read_seq);
            con->receiver.last_read_seq ++;
        } else {
            int cat_mai_incape = len - size;
            memcpy(buffer + size, pachet_curent.data(), cat_mai_incape);
            size = size + cat_mai_incape;
            // Stergem pachetul consumat complet si trecem la urmatorul
            con->receiver.recv_buffer_used = actualizeaza_spatiu_buffer(con->receiver.recv_buffer_used, cat_mai_incape);
            //
            fereastra[con->receiver.last_read_seq].erase(pachet_curent.begin(), pachet_curent.begin() + cat_mai_incape);
            break;
        }
    }
    if (size > 0) {
        send_ctrl_packet(con, ACK, con->receiver.expected_seq);
    }
    pthread_mutex_unlock(&cons[conn_id]->con_lock);
    return size;
}

void *receiver_handler(void *arg)
{

    char segment[MAX_SEGMENT_SIZE];
    int res;
    DEBUG_PRINT("Starting recviver handler\n");

    while (1) {

        int conn_id = -1;
        do {
            res = recv_message_or_timeout(segment, MAX_SEGMENT_SIZE, &conn_id);
        } while(res == -14);
        if (res == -1) {
            continue;
        }

        if (conn_id < 0 || cons.find(conn_id) == cons.end()) {
            continue;
        }
        pthread_mutex_lock(&cons[conn_id]->con_lock);

        /* Handle segment received from the sender. We use this between locks
        as to not have synchronization issues with the recv_data calls which are
        on the main thread */

        //cautam in map conexiunea asociata id-ului conn_id
        struct connection *con = cons[conn_id];
        // Mapam segmentul primit peste structura header-ului de date pentru a accesa metadatele
        struct poli_tcp_data_hdr *segment_date = (struct poli_tcp_data_hdr *)segment;
        //acceptam pachetul doar daca are id_ul corect
        if (segment_date->protocol_id == POLI_PROTOCOL_ID && segment_date->type == DATA  && segment_date->conn_id == con->conn_id){
            uint16_t nr_secventa = ntohs(segment_date->seq_num);
            uint16_t len = ntohs(segment_date->len);
            // Verificam daca numarul de secventa se incadreaza in limitele ferestrei active:
            // Mai mare sau egal cu marginea stanga (expected_seq) si mai mic decat marginea dreapta
            if (nr_secventa >= con->receiver.expected_seq && nr_secventa < con->receiver.expected_seq + con->receiver.window_size) {
                //daca nr de aparitii este 0 inseamna ca pachetul nu este in map
                if (con->receiver.fereastra_glisanta_primita.count(nr_secventa) == 0) {
                    //calculam adresa de inceput a datelor
                    // Cream un vector cu octetii payload-ului de lungime len
                    if (con->receiver.recv_buffer_used + len <= con->receiver.buffer_cap) {
                        char *payload = segment + sizeof(struct poli_tcp_data_hdr);
                        con->receiver.fereastra_glisanta_primita[nr_secventa] =
                            std::vector<char>(payload, payload + len);
                        con->receiver.recv_buffer_used += len;
                    }
                }
                // Glisam marginea stanga a ferestrei in avans atata timp cat gasim pachete consecutive
                // stocate cu succes in map-ul nostru
                while (con->receiver.fereastra_glisanta_primita.count(con->receiver.expected_seq) != 0) {
                    con->receiver.expected_seq++;
                }
            }
            //raspuns ack
            send_ctrl_packet(con, ACK, con->receiver.expected_seq);
        }

        pthread_mutex_unlock(&cons[conn_id]->con_lock);
    }

}

//ma uit in functia asta restul par ok
int wait4connect(uint32_t ip, uint16_t port)
{
    /* TODO: Implement the Three Way Handshake on the receiver part. This blocks
     * until a connection is established. */
    struct sockaddr_in client_addr;
    socklen_t clen = sizeof(client_addr);
    struct poli_tcp_ctrl_hdr pack;
    //alocam noua conexiune
    struct connection *con = new connection{};
    static int conn_id = 0;

    con->receiver.expected_seq = 0;
    con->receiver.last_read_seq = 0;

    con->receiver.buffer_size = tmp_buffer_bytes;
    con->receiver.window_size = con->receiver.buffer_size / MAX_DATA_SIZE;
    //
    if (con->receiver.window_size <= 0) {
        con->receiver.window_size = 1;
    }
    con->receiver.buffer_cap = tmp_buffer_bytes;
    con->receiver.recv_buffer_used = 0;
    //
    /* Receive SYN on the connection socket. Create a new socket and bind it to
     * the chosen port. Send the data port number via SYN-ACK to the client */

    //asteptam sa primim SYN
    while (1) {
        int bytesread = recvfrom(listenfd, &pack, sizeof(struct poli_tcp_ctrl_hdr), 0,
                   (struct sockaddr *)&client_addr, &clen);
        assert(bytesread >= 0);
        if (pack.protocol_id != POLI_PROTOCOL_ID)
            continue;
        if (pack.type == SYN)
            break;
    }
    con->sockfd = socket(AF_INET, SOCK_DGRAM, 0); //cream noul socket
    con->conn_id = conn_id;
    int client_id = conn_id;
    conn_id ++;
    con->servaddr = client_addr; //salvam datele clientului

    struct sockaddr_in myaddr;
    memset(&myaddr, 0, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = INADDR_ANY;
    myaddr.sin_port = htons(0);

    int enable = 1;
    setsockopt(con->sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

    int ret = bind(con->sockfd, (const struct sockaddr *)&myaddr, sizeof(myaddr));
    assert(ret == 0);

    // Aflam ce port dinamic ne-a alocat sistemul
    struct sockaddr_in allocated_addr;
    socklen_t addr_len = sizeof(allocated_addr);
    getsockname(con->sockfd, (struct sockaddr *)&allocated_addr, &addr_len);
    uint16_t chosen_data_port = ntohs(allocated_addr.sin_port);

    //trimitem SYN_ACK cu portul
    struct poli_tcp_ctrl_hdr reply;
    memset(&reply, 0, sizeof(struct poli_tcp_ctrl_hdr));
    reply.protocol_id = POLI_PROTOCOL_ID;
    reply.conn_id = con->conn_id;
    reply.type = SYN_ACK;

    reply.ack_num = htons(0);
    reply.recv_window = htons((uint16_t)con->receiver.buffer_cap);

    uint16_t port_net = htons(chosen_data_port);

    char syn_ack_packet[sizeof(struct poli_tcp_ctrl_hdr) + sizeof(uint16_t)];

    memcpy(syn_ack_packet, &reply, sizeof(reply));
    memcpy(syn_ack_packet + sizeof(reply), &port_net, sizeof(uint16_t));
    //
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 200000;
    if (setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0)
        perror("Error");
    while (1) {
        int rc = sendto(listenfd, syn_ack_packet, sizeof(syn_ack_packet), 0, (struct sockaddr *)&client_addr, clen);
        assert(rc >= 0);
        int bytesread = recvfrom(con->sockfd, &pack,sizeof(struct poli_tcp_ctrl_hdr), 0, NULL, NULL);
        if (bytesread < 0) {
            continue; // timeout, retrimitem SYN_ACK
        }
        if (pack.protocol_id != POLI_PROTOCOL_ID)
            continue;
        if (pack.type == ACK && pack.conn_id == client_id)
            break;
    }
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    pthread_mutex_init(&con->con_lock, NULL);
    cons.insert({client_id, con});

    data_fds[fdmax].fd = con->sockfd;
    data_fds[fdmax].events = POLLIN;

    timer_fds[fdmax].fd = timerfd_create(CLOCK_REALTIME,  0);
    timer_fds[fdmax].events = POLLIN;

    struct itimerspec spec;
    spec.it_value.tv_sec = 1;
    spec.it_value.tv_nsec = 0;
    spec.it_interval.tv_sec = 1;
    spec.it_interval.tv_nsec = 0;

    timerfd_settime(timer_fds[fdmax].fd, 0, &spec, NULL);
    fdmax++;

    DEBUG_PRINT("Connection established!");

    return client_id;
}

void init_receiver(int recv_buffer_bytes)
{
    pthread_t thread1;
    int ret;
    tmp_buffer_bytes = recv_buffer_bytes;
    /* TODO: Create the connection socket and bind it to 8031 */
    struct sockaddr_in servaddr;
    uint16_t port = 8032;

    if ((listenfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    int enable = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(port);

    ret = bind(listenfd, (const struct sockaddr *)&servaddr, sizeof(servaddr));
    assert(ret == 0);

    ret = pthread_create( &thread1, NULL, receiver_handler, NULL);
    assert(ret == 0);
}
