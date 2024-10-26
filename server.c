#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>



#define VERBOSITY_ERROR 1
#define VERBOSITY_WARN 2
#define VERBOSITY_INFO 4
#define VERBOSITY_DEBUG 10

#define MSG_ERROR "[\x1B[31mERROR\x1B[0m] "
#define MSG_WARN "[\x1B[33mWARN\x1B[0m] "
#define MSG_INFO "[\x1B[32mINFO\x1B[0m] "


union sockaddr_in_u{
	struct sockaddr_in ipv4;
	struct sockaddr_in6 ipv6;
};
union ip_addr_u{
	int ipv4;
	struct in6_addr ipv6;
};

bool str_equal(const char*, const char*);
int get_address_family(const char*);

int main(int argc, char *argv[]){
	
	unsigned int verbosity = VERBOSITY_WARN;
	unsigned short listen_ip_argv_pos = 0, listen_port_argv_pos = 0;
	
	unsigned short listen_port = 0;
	union sockaddr_in_u sock_server, sock_client;
	union ip_addr_u listen_addr = {0};
	int listen_ip_family = AF_INET;
	
	
	for (int i = 1; i < argc; i++){
		
		if (str_equal(argv[i], "-h") || str_equal(argv[i], "--help")){
			
			printf("\n    [USAGE]\n"
				   "  [--listen, -l <ip>]\n"
				   "  [--listen-port, -lp <port>]\n\n");
			
			return 0;
		}
		else if (str_equal(argv[i], "-v") || str_equal(argv[i], "--verbosity")){
			i++;
			if (argc == i){
				puts(MSG_ERROR "Missing number.");
				return 1;
			}
			
			if (str_equal(argv[i], "error"))
				verbosity = VERBOSITY_ERROR;
			else if (str_equal(argv[i], "warn") || str_equal(argv[i], "warning"))
				verbosity = VERBOSITY_WARN;
			else if (str_equal(argv[i], "info"))
				verbosity = VERBOSITY_INFO;
			else if (str_equal(argv[i], "debug"))
				verbosity = VERBOSITY_DEBUG;
			else
				verbosity = atoi(argv[i]);
			
		}
		else if (str_equal(argv[i], "-l") || str_equal(argv[i], "--listen")){
			i++;
			if (argc == i){
				puts(MSG_ERROR "Missing address.");
				return 1;
			}

			listen_ip_family = get_address_family(argv[i]);
			if (inet_pton(listen_ip_family, argv[i], &listen_addr) != 1){
				printf(MSG_ERROR "Bad IP address '%s'\n", argv[i]);
				return 1;
			}
			
			listen_ip_argv_pos = i;
		}
		else if (str_equal(argv[i], "-lp") || str_equal(argv[i], "--listen-port")){
			i++;
			if (argc == i){
				puts(MSG_ERROR "Missing port.");
				return 1;
			}
			listen_port = strtoul(argv[i], NULL, 10);
			if (listen_port == 0 || listen_port > 0xFFFF){
				printf(MSG_ERROR "Bad port '%s'.\n", argv[i]);
				return 1;
			}
			
			listen_port_argv_pos = i;
		}
		else{
			printf(MSG_ERROR "Invalid argument: '%s'\n", argv[i]);
			return 1;
		}
		
	}
	
	
	if (listen_port == 0){
		puts(MSG_ERROR "Missing argument:\n\t--listen-port\n");
		return 1;
	}

	if (listen_ip_family == AF_INET){
		sock_server.ipv4.sin_family = listen_ip_family;
		sock_server.ipv4.sin_addr.s_addr = listen_addr.ipv4;
		sock_server.ipv4.sin_port = htons(listen_port);
	}else if (listen_ip_family == AF_INET6){
		sock_server.ipv6.sin6_family = listen_ip_family;
		memcpy(&sock_server.ipv6.sin6_addr, &listen_addr.ipv6, sizeof listen_addr);
		sock_server.ipv6.sin6_port = htons(listen_port);
	}
	else{
		puts(MSG_ERROR "Unsupported IP family.");
		return 1;
	}
	
	
	int server_socket;
	unsigned int sizeof_sockaddr = sizeof(struct sockaddr);
	
	server_socket = socket(listen_ip_family, SOCK_DGRAM, 0);
	if (server_socket == -1) {
		perror(MSG_ERROR "socket()");
		return 1;
	}
	

	int option = 1;
	if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof option) == -1){
		perror(MSG_ERROR "setsockopt(SO_REUSEADDR)");
		return 1;
	}
	
	if (bind(server_socket, (struct sockaddr*)&sock_server, sizeof sock_server) != 0) {
		perror(MSG_ERROR "bind()");
		return 1;
	}
	
	printf(MSG_INFO "Waiting for packets on port %d\n", listen_port);
	
	char packet[512];
	char *packet_reply = 0;
	int reply_size = 0;
	int packet_size;

	while (true){

		packet_size = recvfrom(server_socket, packet, sizeof packet, 0, (struct sockaddr*)&sock_client, &sizeof_sockaddr);
		if (packet_size <= 0){
			perror(MSG_ERROR "recvfrom()");
			continue;
		}

		if (packet_size < 500){
			// This is a technique to mitigate UDP amplification
			// The attacker would need to send way more data than this program will respond
			// This makes it uninteresting for DDoS

			if (verbosity >= VERBOSITY_WARN){
				printf(MSG_WARN "Received packet with size %d bytes\n", packet_size);
			}

			continue;		// Drop packet if under 500 bytes
		}
		
		if (verbosity >= VERBOSITY_DEBUG){
			printf("Packet dump (%db):  ", packet_size);
			
			for (unsigned short i = 0; i < packet_size; i++){
				printf("%02X ", packet[i]);
			}
			puts("\n");
		}
		
		// If the first byte is 0x00, reply with the remote IP as a 4-bytes binary representation
		if (packet[0] == 0){
			if (listen_ip_family == AF_INET){
				packet_reply = (char*)&sock_client.ipv4.sin_addr.s_addr;
				reply_size = 4;
			}
		}
		else if (packet[0] == 1){
			// We use packet as a buffer to store the new string representation
			inet_ntop(listen_ip_family, listen_ip_family == AF_INET ? &sock_client.ipv4.sin_addr.s_addr : (in_addr_t*)&sock_client.ipv6.sin6_addr, packet, sizeof packet);
		}
		else{
			if (verbosity >= VERBOSITY_DEBUG){
				printf(MSG_INFO "Unknown packet type: %02X\n", packet[0]);
			}

			// Silently drop packet
			continue;
		}

		if (verbosity >= VERBOSITY_INFO)
			printf(MSG_INFO "Packet from %s\n", packet);
		
		// We point the reply pointer to the buffer containing the IP
		packet_reply = packet;
		reply_size = strlen(packet);
		
		
		packet_size = sendto(server_socket, packet_reply, reply_size, 0, (struct sockaddr*)&sock_client, sizeof sock_client);
		if (packet_size == -1){
			perror(MSG_ERROR "Failed to reply to client request");
			continue;
		}
		
	}
}

bool str_equal(const char *str1, const char *str2){
	unsigned int index = 0;
	while (str1[index] != 0 && str2[index] != 0) {
		if (str1[index] != str2[index]) {
			return false;
		}
		index++;
	}
	return str1[index] == str2[index] ? true : false;
}

int get_address_family(const char *ip){
	size_t length = strlen(ip);
	for (size_t i = 0; i < length; i++){
		if (ip[i] == ':'){
			return AF_INET6;
		}
	}

	return AF_INET;
}
