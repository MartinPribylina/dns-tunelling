#include "dns_sender_events.h"
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>

#include "../base32.h"
#include "../dns.h"

#define NETADDR_STRLEN (INET6_ADDRSTRLEN > INET_ADDRSTRLEN ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN)
#define CREATE_IPV4STR(dst, src) char dst[NETADDR_STRLEN]; inet_ntop(AF_INET, src, dst, NETADDR_STRLEN)
#define CREATE_IPV6STR(dst, src) char dst[NETADDR_STRLEN]; inet_ntop(AF_INET6, src, dst, NETADDR_STRLEN)



void CheckIfIsNextArgument(int argc, int pos)
{
	if (argc < pos)
	{
		fprintf(stderr,"Wrong number of arguments\n");
        exit(EXIT_FAILURE);
	}
	
}

void ProcessArguments(int argc, char **argv, bool *upstream_dns_bool, char *upstream_dns, char *base_host, char *dst_filepath, bool *src_filepath_bool, char *src_filepath)
{

	int pos = 1;
	if (!strcmp(argv[pos], "-u"))
	{
		*upstream_dns_bool = true;
		pos++;
		strcpy(upstream_dns, argv[pos]);
		pos++;
	}
	CheckIfIsNextArgument(argc, pos);
	strcpy(base_host, argv[pos]);
	pos++;
	CheckIfIsNextArgument(argc, pos);
	strcpy(dst_filepath, argv[pos]);
	pos++;
	if (argc > pos)
	{
		*src_filepath_bool = true;
		strcpy(src_filepath, argv[pos]);
	}

	if (*src_filepath_bool == false)
	{
		src_filepath = "stdin";
	}
	
}

void send_packet(unsigned char *name_prefix_buf, size_t name_prefix_size,
                    struct sockaddr_in server_address, int sockfd,
					char *base_host, uint16_t session_id, char *dst_filepath, bool last);

int random_unsigned(int max){
    int number = rand() % max;
    return number; 
}

int main(int argc, char *argv[])
{
	if (argc < 2)
    {
        fprintf(stderr,"Wrong number of arguments\n");
        exit(EXIT_FAILURE);
    }

	bool upstream_dns_bool = false;
	char ip_address[128] = "";
	char base_host[128] = "";
	char dst_filepath[128] = "";
	bool src_filepath_bool = false;
	char src_filepath[128] = "";

	ProcessArguments(argc, argv, &upstream_dns_bool, ip_address, base_host, dst_filepath, &src_filepath_bool, src_filepath);

	if (!upstream_dns_bool)
	{
		FILE *cmd;
		char result[1024];

		cmd = popen("grep \"nameserver\" /etc/resolv.conf", "r");
		if (cmd == NULL) {
			perror("failed to open /etc/resolv.conf");
			exit(EXIT_FAILURE);
		}

		fgets(result, sizeof(result), cmd);

		char *token = strtok(result, " ");
		token = strtok(NULL, " ");
		token[strcspn(token, "\n")] = 0;

		strcpy(ip_address, token);
		pclose(cmd);
	}

	//Keeping space for base_host in QNAME
	int base_host_length = strlen(base_host) + 2;
	//In order to encode full message sucesfully we need to left space so full encoded message will fit to QNAME (255)
	int available_space_for_data = (QNAME_LENGTH / 100 * 70) - base_host_length;
	
	struct in_addr in_addr_ip;
	if (!inet_aton(ip_address, &in_addr_ip))  // Check if IPV4 is correct and convert
	{
		perror("ip_address should be an IPv4 address.");
		exit(EXIT_FAILURE);
	}

	FILE *fin;
	if (src_filepath_bool)
	{
		fin = fopen(src_filepath, "r");
	}
	else
	{
		fin = stdin;
	}

	if (!fin) {
		fprintf(stderr, "Unable to open file %s for reading.\n", src_filepath);
		exit(EXIT_FAILURE);
	}

	int sockfd; 
    struct sockaddr_in servaddr; 

    // Creating socket file descriptor 
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 
    
    memset(&servaddr, 0, sizeof(servaddr)); 
        
    // Filling address information 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_port = htons(PORT); 
    servaddr.sin_addr = in_addr_ip; 

	dns_sender__on_transfer_init(&servaddr.sin_addr);

	//stores encoded data, base_host_length keeps space for base_host so it will fit into QNAME (255)
	int data_buffer_size = QNAME_LENGTH - base_host_length;
	unsigned char base32_data_buffer[data_buffer_size];
	size_t file_size = 0;
	uint16_t session_id = 0;
	struct dns_payload payload;
	payload.sequence = 0;
	payload.last = 0;
	strcpy(payload.dst_filepath, dst_filepath);
	while (1) {
		memset(payload.data, 0, BLOCKSIZE);
		memset(base32_data_buffer, 0, data_buffer_size);
		payload.length = (uint8_t)fread(payload.data, 1, BLOCKSIZE, fin);
		file_size += payload.length;

		if (payload.length != available_space_for_data && ferror(fin)) {
			fprintf(stderr, "Unable to read file\n");
			exit(-1);
		}

		size_t encoded_data_length =
			base32_encode((uint8_t *)&payload,
						sizeof(struct dns_payload) - BLOCKSIZE + payload.length,
						(uint8_t *)base32_data_buffer, QNAME_LENGTH - base_host_length);
		base32_data_buffer[encoded_data_length] = '\0';
		session_id = random_unsigned(65536);

		if (payload.last == 0)
		{
			//Encoded data with basehost
			char encoded_data[255];
			strcpy(encoded_data, (char*)base32_data_buffer);
			strcat(encoded_data, ".");
			strcat(encoded_data, base_host);
			dns_sender__on_chunk_encoded(dst_filepath, session_id, encoded_data);
		}
		
		send_packet(base32_data_buffer, encoded_data_length, servaddr, sockfd, base_host, session_id, dst_filepath, payload.last == 1);
		payload.sequence++;
		char response[1024];
		socklen_t socklen = sizeof(struct sockaddr_in);
		int num_received = 0;
		if ((num_received = recvfrom(sockfd, response, sizeof(response), MSG_WAITALL,
							(struct sockaddr *)&servaddr, &socklen)) == -1) {
			perror("receive failed");
			exit(EXIT_FAILURE);
		}

		if (feof(fin))
		{
			if (payload.last == 1)
			{
				break;
			}
			payload.last = 1;
		}
	}

	dns_sender__on_transfer_completed(src_filepath, file_size);
	fclose(fin);
    close(sockfd); 
    return 0; 
}

void send_packet(unsigned char *name_prefix_buf, size_t name_prefix_size,
                    struct sockaddr_in server_address, int sockfd,
					char *base_host, uint16_t session_id, char *dst_filepath, bool last)
{
	unsigned char dns_buf[PACKET_MAXSIZE];
	memset(dns_buf, 0, PACKET_MAXSIZE);
	struct dns_header *header = (struct dns_header *)dns_buf;
	header->id = session_id;
	header->rd = 1;
	header->qdcount = htons(1);

	unsigned char *dns_buf_ptr = dns_buf + sizeof(struct dns_header*);

	int number_of_labels = name_prefix_size / LABEL_LENGTH;
	if (name_prefix_size % LABEL_LENGTH > 0)
	{
		number_of_labels++;
	}
	
	for (int i = 0; i < number_of_labels; i++)
	{
		size_t label_start = i * LABEL_LENGTH;
		size_t count = LABEL_LENGTH;
		if (label_start + LABEL_LENGTH >= name_prefix_size)
		{
			count = name_prefix_size - label_start;
		}
		*dns_buf_ptr = (unsigned char) count;
		dns_buf_ptr++;
		memcpy(dns_buf_ptr, name_prefix_buf + label_start, count);
		dns_buf_ptr += count;
	}
	char tmp_base_host[strlen(base_host)];
	memset(tmp_base_host, 0, strlen(base_host));
	memcpy(tmp_base_host, base_host, strlen(base_host));
	tmp_base_host[strlen(base_host)] = '\0';
	char *token = strtok(tmp_base_host, ".");
	*dns_buf_ptr = (unsigned char) strlen(token);
	dns_buf_ptr++;
	memcpy(dns_buf_ptr, token, strlen(token));
	dns_buf_ptr += strlen(token);
	token = strtok(NULL, ".");
	*dns_buf_ptr = (unsigned char) strlen(token);
	dns_buf_ptr++;
	memcpy(dns_buf_ptr, token, strlen(token));
	dns_buf_ptr += strlen(token);
	*dns_buf_ptr = (unsigned char)0;
	dns_buf_ptr++;

	*((uint16_t *)(dns_buf_ptr)) = htons(1);
	dns_buf_ptr += 2;
  	*((uint16_t *)(dns_buf_ptr)) = htons(1);
	size_t buf_size = dns_buf_ptr - dns_buf;
	
	
	sendto(sockfd, dns_buf, buf_size, 
		0, (const struct sockaddr *) &server_address,  
			sizeof(server_address)); 
	
	if (!last)
	{
		dns_sender__on_chunk_sent(&server_address.sin_addr, dst_filepath, session_id, name_prefix_size);
	}
}

void dns_sender__on_chunk_encoded(char *filePath, int chunkId, char *encodedData)
{
	fprintf(stderr, "[ENCD] %s %9d '%s'\n", filePath, chunkId, encodedData);
}

void on_chunk_sent(char *source, char *filePath, int chunkId, int chunkSize)
{
	fprintf(stderr, "[SENT] %s %9d %dB to %s\n", filePath, chunkId, chunkSize, source);
}

void dns_sender__on_chunk_sent(struct in_addr *dest, char *filePath, int chunkId, int chunkSize)
{
	CREATE_IPV4STR(address, dest);
	on_chunk_sent(address, filePath, chunkId, chunkSize);
}

void dns_sender__on_chunk_sent6(struct in6_addr *dest, char *filePath, int chunkId, int chunkSize)
{
	CREATE_IPV6STR(address, dest);
	on_chunk_sent(address, filePath, chunkId, chunkSize);
}

void on_transfer_init(char *source)
{
	fprintf(stderr, "[INIT] %s\n", source);
}

void dns_sender__on_transfer_init(struct in_addr *dest)
{
	CREATE_IPV4STR(address, dest);
	on_transfer_init(address);
}

void dns_sender__on_transfer_init6(struct in6_addr *dest)
{
	CREATE_IPV6STR(address, dest);
	on_transfer_init(address);
}

void dns_sender__on_transfer_completed( char *filePath, int fileSize)
{
	fprintf(stderr, "[CMPL] %s of %dB\n", filePath, fileSize);
}