#include <pthread.h>
#include <cstdlib>
#include <map>
#include <cstdint>
#include "lib.h"
#include "utils.h"
#include "protocol.h"
#include <cassert>
#include <poll.h>
#include <sys/timerfd.h>
#include <cstring>
#include <unistd.h>

using namespace std;
typedef std::map<uint16_t, std::vector<char>>::iterator map_iterator;

std::map<int, struct connection *> cons;

struct pollfd data_fds[MAX_CONNECTIONS];
/* Used for timers per connection */
struct pollfd timer_fds[MAX_CONNECTIONS];
int fdmax = 0;
int window_size;

//functie care calculeaza cati octeti de date au fost trimisi pe retea
int get_bytes_in_flight(struct connection *con)
{
    int bytes = 0;
    std::map<uint16_t, std::vector<char>>::iterator it;

    for (it = con->sender.fereastra_glisanta_trimisa.begin();
         it != con->sender.fereastra_glisanta_trimisa.end();
         it++)
    {
        int dimensiune_pachet = it->second.size();
        bytes += (dimensiune_pachet - sizeof(struct poli_tcp_data_hdr));
    }

    return bytes;
}

int send_data(int conn_id, char *buffer, int len)
{
    int size = 0;
    // Verificam daca ID-ul conexiunii este valid si exista in map-ul global
    if (cons.find(conn_id) == cons.end()) {
        return -1;
    }
    pthread_mutex_lock(&cons[conn_id]->con_lock);

    /* We will write code here as to not have sync problems with sender_handler */
    struct connection *con = cons[conn_id];
    //respingem datele daca depasesc capacitatea bufferului de trimitere
    if (con->sender.bytes_used + len > con->sender.buffer_cap) {
        pthread_mutex_unlock(&cons[conn_id]->con_lock);
        return -1;
    }
    // Impartim fluxul de date in pachete de dimensiune maxima
    while (size < len) {
        // Calculam dimensiunea payload-ului curent
        int cat_punem = (len - size > MAX_DATA_SIZE) ? MAX_DATA_SIZE : len - size;
        // Copiem chunk-ul de date direct din bufferul utilizatorului intr-un vector temporar
        std::vector<char> bucata(buffer + size, buffer + size + cat_punem);
        con->sender.buffer.push(bucata);
        con->sender.bytes_used += cat_punem;
        size += cat_punem;
    }
    pthread_mutex_unlock(&cons[conn_id]->con_lock);

    return size;
}

void *sender_handler(void *arg)
{
    int res = 0;
    char buf[MAX_SEGMENT_SIZE];

    while (1) {
        if (cons.size() == 0) {
            usleep(10000);//
            continue;
        }
    std::map<int, struct connection *>::iterator it_con;

    for (it_con = cons.begin(); it_con != cons.end(); it_con++) {
        struct connection *con = it_con->second;

        pthread_mutex_lock(&con->con_lock);

        while (con->sender.buffer.empty() == false) {
            int pachete_in_zbor;
            pachete_in_zbor = con->sender.fereastra_glisanta_trimisa.size();

        if (pachete_in_zbor >= con->sender.max_window_seq)
            break;

        int bytes_in_zbor = get_bytes_in_flight(con);

        std::vector<char> payload;
        payload = con->sender.buffer.front();
        int len_payload;
        len_payload = payload.size();

        if (bytes_in_zbor + len_payload > con->sender.spatiu_liber_receptor) {
            break;
        }

        int dim_pachet;
        dim_pachet = sizeof(struct poli_tcp_data_hdr) + len_payload;

        std::vector<char> pachet_complet;
        pachet_complet.resize(dim_pachet);

        struct poli_tcp_data_hdr *pack;
        pack = (struct poli_tcp_data_hdr *)pachet_complet.data();

        pack->protocol_id = POLI_PROTOCOL_ID;
        pack->conn_id = con->conn_id;
        pack->type = DATA;
        pack->seq_num = htons(con->sender.next_seq);
        pack->len = htons(len_payload);

        memcpy(pachet_complet.data() + sizeof(struct poli_tcp_data_hdr), payload.data(), len_payload);

        int rc;
        rc = sendto(con->sockfd, pachet_complet.data(), pachet_complet.size(), 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));
        assert(rc >= 0);

        con->sender.fereastra_glisanta_trimisa[con->sender.next_seq] = pachet_complet;
        con->sender.next_seq = con->sender.next_seq + 1;
        con->sender.bytes_used = con->sender.bytes_used - len_payload;

        if (con->sender.bytes_used < 0) {
            con->sender.bytes_used = 0;
        }
        con->sender.buffer.pop();
    }

    pthread_mutex_unlock(&con->con_lock);
}
        int conn_id = -1;
        do {
            res = recv_message_or_timeout(buf, MAX_SEGMENT_SIZE, &conn_id);
        } while(res == -14);
        if (conn_id < 0 || cons.find(conn_id) == cons.end()) {
            continue;
        }
        //
        pthread_mutex_lock(&cons[conn_id]->con_lock);

        /* Handle segment received from the receiver. We use this between locks
        as to not have synchronization issues with the send_data calls which are
        on the main thread */

        //daca res = -1 a expirat timerul,pachetul trebuie retrimis
        //res > 0 am primit ceva pe socket , -14 = nu s a intamplat nimic
        struct connection *con = cons[conn_id];
        struct poli_tcp_ctrl_hdr *segment_ctrl = (struct poli_tcp_ctrl_hdr *)buf;
        if (res == -1) {
            //timerul conexiunii a expirat
            //trebuie sa retrimitem toata fereastra
            map_iterator i = con->sender.fereastra_glisanta_trimisa.begin();
            while (i != con->sender.fereastra_glisanta_trimisa.end() ) {
                int rc = sendto(con->sockfd, i->second.data(), i->second.size(), 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));
                assert(rc >= 0);
                i++;
            }
            pthread_mutex_unlock(&cons[conn_id]->con_lock);
            continue;
        } else if (res >= (int)sizeof(struct poli_tcp_ctrl_hdr) &&
           segment_ctrl->protocol_id == POLI_PROTOCOL_ID &&
           segment_ctrl->type == ACK &&
           segment_ctrl->conn_id == con->conn_id) {
            uint16_t ack_num = ntohs(segment_ctrl->ack_num);
            if (ack_num > con->sender.next_seq) {
                ack_num = con->sender.next_seq;
            }
            if (ack_num > con->sender.base_seq) {
                for (int i = con->sender.base_seq; i < ack_num; i++) {
                    con->sender.fereastra_glisanta_trimisa.erase(i);
                }
                con->sender.base_seq = ack_num;
            }
            con->sender.spatiu_liber_receptor = ntohs(segment_ctrl->recv_window);
           }
        if (res >= (int)sizeof(struct poli_tcp_ctrl_hdr) && segment_ctrl->protocol_id == POLI_PROTOCOL_ID && segment_ctrl->type == SYN_ACK && segment_ctrl->conn_id == con->conn_id) {
            struct poli_tcp_ctrl_hdr ack;
            memset(&ack, 0, sizeof(ack));
            ack.protocol_id = POLI_PROTOCOL_ID;
            ack.conn_id = con->conn_id;
            ack.type = ACK;
            ack.ack_num = htons(0);
            ack.recv_window = htons(0);

            int rc = sendto(con->sockfd, &ack, sizeof(ack), 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));

            assert(rc >= 0);
    }
        pthread_mutex_unlock(&cons[conn_id]->con_lock);
    }
}

int setup_connection(uint32_t ip, uint16_t port)
{
    /* Implement the sender part of the Three Way Handshake. Blocks
    until the connection is established */

    struct connection *con = new connection{};//(struct connection *)malloc(sizeof(struct connection));
    int conn_id = 0;
    con->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    con->sender.base_seq = 0;
    con->sender.next_seq = 0;
    con->sender.max_window_seq = window_size;
    con->sender.spatiu_liber_receptor = MAX_DATA_SIZE;
    con->sender.bytes_used = 0;
    con->sender.buffer_cap = 256 * 1024;

    if (con->sender.max_window_seq <= 0) {
        con->sender.max_window_seq = 1;
    }

    struct sockaddr_in addr;
    socklen_t slen = sizeof(struct sockaddr_in);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip;
    addr.sin_port = port;

    /* We will send the SYN on 8031. Then we will receive a SYN-ACK with the connection
     * port. We can use con->sockfd for both cases, but we will need to update server_addr
     * with the port received via SYN-ACK */
    struct poli_tcp_ctrl_hdr send;
    memset(&send, 0, sizeof(struct poli_tcp_ctrl_hdr));
    send.protocol_id = POLI_PROTOCOL_ID;
    send.type = SYN;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 200000;

    int ret = setsockopt(con->sockfd,SOL_SOCKET,SO_RCVTIMEO, &tv, sizeof(tv));
    assert(ret == 0);
    //asteptam sa primim SYN-ACK
    struct poli_tcp_ctrl_hdr pack_primit;
    char recv_buf[sizeof(struct poli_tcp_ctrl_hdr) + sizeof(uint16_t)];

    while (1) {
        int rc = sendto(con->sockfd, &send, sizeof(send), 0, (struct sockaddr *)&addr, slen);
        assert(rc >= 0);
        int bytesread = recvfrom(con->sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&addr, &slen);
        if (bytesread < 0) {
            continue;
        }
        if (bytesread < (int)(sizeof(struct poli_tcp_ctrl_hdr) + sizeof(uint16_t))) {
            continue;
        }
        memcpy(&pack_primit, recv_buf, sizeof(struct poli_tcp_ctrl_hdr));
        if (pack_primit.protocol_id == POLI_PROTOCOL_ID &&
            pack_primit.type == SYN_ACK) {
            break;
            }
    }
    uint16_t port_net;
    memcpy(&port_net, recv_buf + sizeof(struct poli_tcp_ctrl_hdr), sizeof(uint16_t));
    uint16_t data_port = ntohs(port_net);
    con->conn_id = pack_primit.conn_id;
    conn_id = pack_primit.conn_id;
    con->sender.spatiu_liber_receptor = ntohs(pack_primit.recv_window);
    if (con->sender.spatiu_liber_receptor <= 0) {
        con->sender.spatiu_liber_receptor = MAX_DATA_SIZE;
    }

    addr.sin_port = htons(data_port);
    con->servaddr = addr; // O salvam in structura conexiunii pentru viitoarele trimiteri
    memset(&send, 0, sizeof(struct poli_tcp_ctrl_hdr));
    send.protocol_id = POLI_PROTOCOL_ID;
    send.type = ACK;
    send.conn_id = con->conn_id;
    int rc = sendto(con->sockfd, &send, sizeof(send), 0, (struct sockaddr *)&con->servaddr,slen);
    assert( rc >= 0);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    pthread_mutex_init(&con->con_lock, NULL);
    cons.insert({conn_id, con});
    /* Since we can have multiple connection, we want to know if data is available
       on the socket used by a given connection. We use POLL for this */
    data_fds[fdmax].fd = con->sockfd;
    data_fds[fdmax].events = POLLIN;

    /* This creates a timer and sets it to trigger every 1 sec. We use this
       to know if a timeout has happend on our connection */
    timer_fds[fdmax].fd = timerfd_create(CLOCK_REALTIME,  0);
    timer_fds[fdmax].events = POLLIN;
    struct itimerspec spec;
    spec.it_value.tv_sec = 0;
    spec.it_value.tv_nsec = 50000000;
    spec.it_interval.tv_sec = 0;
    spec.it_interval.tv_nsec = 50000000;
    timerfd_settime(timer_fds[fdmax].fd, 0, &spec, NULL);
    fdmax++;

    DEBUG_PRINT("Connection established!");

    return conn_id;
}

void init_sender(int speed, int delay)
{
    pthread_t thread1;
    int ret;
    //viteza in octeti pe sec
    double speed_bytes_per_sec = (speed * 1000000.0) / 8.0;
    //delay in secunde
    double delay_sec = delay / 1000.0;
    double bdp_bytes = speed_bytes_per_sec * (2 * delay_sec);
    window_size = (int)(bdp_bytes / MAX_DATA_SIZE);
    if (window_size < 16) {
        window_size = 16;
    }
    /* Create a thread that will*/
    ret = pthread_create( &thread1, NULL, sender_handler, NULL);
    assert(ret == 0);
}
