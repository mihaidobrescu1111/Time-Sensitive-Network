#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

struct Packet {
    int vlan_id;
    const u_char *data;
    int length;
};

typedef struct ListPackets {
    struct Packet packet;
    struct ListPackets *next;
} ListPackets;


ListPackets *List[8] = { NULL };
int gate_idx = 0;

pcap_t *pcap_handle;

void insertPacket(int bit113_115, const u_char *data, int length) {
    int index = bit113_115 % 8; 
   
    ListPackets *newPacket = (ListPackets*)malloc(sizeof(ListPackets));
    if (newPacket == NULL) {
        exit(1);
    }
    newPacket->packet.vlan_id = bit113_115;
    newPacket->packet.data = data;
    newPacket->packet.length = length;
    newPacket->next = List[index];
    List[index] = newPacket;

}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_VLAN) {
        int vlan_id = ntohs(*(uint16_t*)(packet + 14 + 2)) & 0x0FFF;
        // gate from bits 112-114
        int gate = 0;
        for (int i = 112; i <= 114; i++) {
            gate |= ((packet[i / 8] >> (7 - i % 8)) & 0x01) << (2 - (i % 8));
        }

        insertPacket(gate, packet, header -> len);
    }
}

void send_packet(u_char *args) {
   
    if (pcap_inject((pcap_t *)args, List[gate_idx]->packet.data, List[gate_idx]->packet.length) <= 0) {
           // fprintf(stderr, "Failed to inject packet\n");
           return 2;
    } else {
           //printf("Packet injected successfully of pri %d\n", gate_idx);
    }

    List[gate_idx] = List[gate_idx]->next;
}


// sleep Thread for gate updates
void *sleepThread(void *arg) {
    while (1) {
        usleep(100000);
        gate_idx = (gate_idx + 1) % 8;
    }
}

// Thread for sending packets
void *sepThread(void *arg) {
    pcap_t *handle = (pcap_t *)arg;
    
    while (1) {
        ListPackets *currentPacket = List[gate_idx];
        int temp_idx = gate_idx;
        while (currentPacket != NULL) {
            if (temp_idx != gate_idx)
                break;
            send_packet((u_char *)handle);
            currentPacket = currentPacket->next;
        }
    }
}

// main Thread for receiving packets
int main(int argc, char **argv) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "vlan";
    bpf_u_int32 net;

    pthread_t sleep_thread_id;
    pthread_t sep_thread_id;

    if (argc != 2) {
       // fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        //fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
        return 2;
    }
    pcap_handle = handle;

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        //fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        //fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pthread_create(&sleep_thread_id, NULL, sleepThread, NULL)) {
        //fprintf(stderr, "Error creating sleep thread\n");
        return 2;
    }

    if (pthread_create(&sep_thread_id, NULL, sepThread, handle)) {
        //fprintf(stderr, "Error creating separation thread\n");
        return 2;
    }

    pcap_loop(handle, -1, process_packet, NULL);
    pcap_close(handle);

    return 0;
}