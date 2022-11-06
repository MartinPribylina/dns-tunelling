#include "dns_receiver_events.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//strcpy, strcmp
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <sys/stat.h>
#include <stdbool.h>
#include <string.h>

#include "../base32.h"
#include "../dns.h"

#define NETADDR_STRLEN (INET6_ADDRSTRLEN > INET_ADDRSTRLEN ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN)
#define CREATE_IPV4STR(dst, src) char dst[NETADDR_STRLEN]; inet_ntop(AF_INET, src, dst, NETADDR_STRLEN)
#define CREATE_IPV6STR(dst, src) char dst[NETADDR_STRLEN]; inet_ntop(AF_INET6, src, dst, NETADDR_STRLEN)
#define MAXLINE 1024 

void save_data(struct dns_query *dns_query, char* dst_path, char *base_host, struct in_addr *source, int session_id);

int main(int argc, char *argv[])
{
	if (argc != 3)
    {
        fprintf(stderr,"Wrong number of arguments\n");
        exit(EXIT_FAILURE);
    }

	char base_host[128] = "";
	char dst_filepath[128] = "";

	strcpy(base_host, argv[1]);
	strcpy(dst_filepath, argv[2]);

    int sockfd;
    unsigned char buffer[PACKET_MAXSIZE];
    struct sockaddr_in servaddr, cliaddr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    socklen_t len = sizeof(cliaddr);

    for (;;) {
        memset(buffer, 0, sizeof(buffer));
        int num_received = recvfrom(sockfd, (char *)buffer, MAX_BUFFER_SIZE,
                                    MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);
        char client_addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(cliaddr.sin_addr), client_addr_str, INET_ADDRSTRLEN);
        
        struct dns_header *header = (struct dns_header *)buffer;

        struct dns_query name_query;
        extract_dns_query(buffer, &name_query);

        save_data(&name_query, dst_filepath, base_host, &cliaddr.sin_addr, header->id);

        CREATE_IPV4STR(address, &cliaddr.sin_addr);
        int response_length = prepare_response(&name_query, buffer, num_received,
                                            600, address);

        if (sendto(sockfd, buffer, response_length, 0, (struct sockaddr *)&cliaddr,
                sizeof(cliaddr)) == -1) {
            perror("sendto failed");
        }
    }

    close(sockfd);
	
    return 0; 
}

int number = 0;

void save_data(struct dns_query *dns_query, char* dst_path, char *base_host, struct in_addr *source, int session_id) {
    char tmp_base_host[255];
    char *tmp_base_host_ptr = tmp_base_host;
    memset(tmp_base_host, 0, 256);
    int len1 = strlen((char*)dns_query->segment[dns_query->num_segments - 2]);
    int len2 = strlen((char*)dns_query->segment[dns_query->num_segments - 1]);
    memccpy(tmp_base_host_ptr, (char*)dns_query->segment[dns_query->num_segments - 2], len1, 255);
    memccpy(tmp_base_host_ptr + len1, ".", 1, 255);
    memccpy(tmp_base_host_ptr + len1 + 1, (char*)dns_query->segment[dns_query->num_segments - 1], len2, 255);
    
    //printf("Base host: %s a: %s b: %s\n",tmp_base_host, (char*)dns_query->segment[dns_query->num_segments - 2], (char*)dns_query->segment[dns_query->num_segments - 1]);

    if (strcmp(tmp_base_host, base_host))
    {
        printf("Basehost doesn't match %s:%s\n", tmp_base_host, base_host);
        //*waiting_new_connection = true;
        return;
    }
    
    uint8_t base32_buf[QNAME_LENGTH] = {0};
    unsigned char *base32_buf_ptr = (unsigned char*)base32_buf;
    for (size_t i = 0; i < dns_query->num_segments - 2; ++i) {
        memcpy(base32_buf_ptr, dns_query->segment[i], strlen(dns_query->segment[i]));
		base32_buf_ptr += strlen(dns_query->segment[i]);
    }
    int data_size = base32_buf_ptr - base32_buf;
    char encoded_data[512];
    snprintf(encoded_data, 512, "%s.%s", base32_buf,tmp_base_host);
    uint8_t payload_buf[QNAME_LENGTH];
    base32_decode(base32_buf, payload_buf, QNAME_LENGTH);

    struct dns_payload *payload = (struct dns_payload *)payload_buf;
    //printf("Payload length: %d sequence: %d last?: %d filepath: %s\n", payload->length, payload->sequence, payload->last, payload->dst_filepath);
    //printf("Payload data: %s\n", payload->data);

    char full_file_name[255];
    char *full_file_name_ptr = full_file_name;
    memset(full_file_name, 0, 255);
    int len3 = strlen(dst_path);
    memccpy(full_file_name_ptr, dst_path, len3, 255);
    memccpy(full_file_name_ptr + len3, "/", 1, 255);
    memccpy(full_file_name_ptr + len3 + 1, payload->dst_filepath, len3, 255);
    if (payload->sequence == 0)
    {
        int ch = '/';
        char * ptr;
        ptr = strrchr( full_file_name_ptr, ch );
        
        char directory_from_client[255];
        strncpy(directory_from_client, full_file_name_ptr, ptr - full_file_name_ptr);
        directory_from_client[ptr - full_file_name_ptr] = '\0';
        mkdir(directory_from_client, 0700);
        FILE *fout = fopen(full_file_name_ptr, "w");
        fprintf(fout, "%s", "");
        fclose(fout);
        dns_receiver__on_transfer_init(source);
    }

    if (payload->last == 1)
    {
        FILE *f = fopen(full_file_name_ptr, "r");
        fseek(f, 0, SEEK_END);
        int size = ftell(f);
        dns_receiver__on_transfer_completed(payload->dst_filepath, size);
        return;
    }

    printf("Filename: %s\n",full_file_name);
    dns_receiver__on_chunk_received(source, payload->dst_filepath, session_id, data_size);
    dns_receiver__on_query_parsed(payload->dst_filepath, encoded_data);

    FILE *fout = fopen(full_file_name_ptr, "a");
    fprintf(fout, "%s", payload->data);
    fclose(fout);
}

void dns_receiver__on_query_parsed(char *filePath, char *encodedData)
{
	fprintf(stderr, "[PARS] %s '%s'\n", filePath, encodedData);
}

void on_chunk_received(char *source, char *filePath, int chunkId, int chunkSize)
{
	fprintf(stderr, "[RECV] %s %9d %dB from %s\n", filePath, chunkId, chunkSize, source);
}

void dns_receiver__on_chunk_received(struct in_addr *source, char *filePath, int chunkId, int chunkSize)
{
	CREATE_IPV4STR(address, source);
	on_chunk_received(address, filePath, chunkId, chunkSize);
}

void dns_receiver__on_chunk_received6(struct in6_addr *source, char *filePath, int chunkId, int chunkSize)
{
	CREATE_IPV6STR(address, source);
	on_chunk_received(address, filePath, chunkId, chunkSize);
}

void on_transfer_init(char *source)
{
	fprintf(stderr, "[INIT] %s\n", source);
}

void dns_receiver__on_transfer_init(struct in_addr *source)
{
	CREATE_IPV4STR(address, source);
	on_transfer_init(address);
}

void dns_receiver__on_transfer_init6(struct in6_addr *source)
{
	CREATE_IPV6STR(address, source);
	on_transfer_init(address);
}

void dns_receiver__on_transfer_completed(char *filePath, int fileSize)
{
	fprintf(stderr, "[CMPL] %s of %dB\n", filePath, fileSize);
}
