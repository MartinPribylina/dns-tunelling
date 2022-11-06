#ifndef _DNS_H
#define _DNS_H 1

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

#define MAX_BUFFER_SIZE 512
#define PACKET_MAXSIZE 512
#define DNS_PORT 53

#define PORT 7080 
#define LABEL_LENGTH 63
#define QNAME_LENGTH 255

#define RESPONSE_SUCCESS 0
#define REPONSE_FORMAT_ERROR 1
#define RESPONSE_FAILURE 2
#define RESPONSE_NAME_ERROR 3
#define RESPONSE_REFUSED 5

#define QTYPE_A 0x01
#define QTYPE_AAAA 0x1C

#define QCLASS_INET 0x0001

#define BLOCKSIZE 120

struct __attribute__((__packed__)) dns_payload {
  uint32_t sequence;
  uint8_t length;
  uint8_t last;
  char dst_filepath[20];
  char data[BLOCKSIZE];
};

struct __attribute__((__packed__)) dns_header {
  uint16_t id;

  unsigned int rd : 1;
  unsigned int tc : 1;
  unsigned int aa : 1;
  unsigned int opcode : 4;
  unsigned int qr : 1;

  unsigned int rcode : 4;
  unsigned int z : 3;
  unsigned int ra : 1;

  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};

struct __attribute__((__packed__)) dns_response_trailer {
  uint8_t ans_type;
  uint8_t name_offset;
  uint16_t type;
  uint16_t qclass;
  uint32_t ttl;
  uint16_t rdlength;
  uint32_t rdata;
};

struct dns_query {
  size_t num_segments;
  char segment[10][64];
  uint16_t type;
  uint16_t qclass;
};

void extract_dns_query(unsigned char *dns_buffer, struct dns_query *name_query);
size_t prepare_response(struct dns_query *name_query, unsigned char *buffer,
                        size_t num_received, uint32_t ttl, char *ip);

#endif