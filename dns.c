#include "dns.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void extract_dns_query(unsigned char *dns_buffer,
                       struct dns_query *name_query) {
  unsigned char *query_ptr = dns_buffer + sizeof(struct dns_header*);
  name_query->num_segments = 0;
  uint8_t segment_size;
  while ((segment_size = *((uint8_t *)query_ptr))) {
    if (segment_size > 63) { // malformed request
      return;
    }
    strncpy(name_query->segment[name_query->num_segments],
            (char *)(query_ptr + 1), segment_size);
    name_query->segment[name_query->num_segments][segment_size] = '\0';
    ++name_query->num_segments;
    
    query_ptr += segment_size + 1;
  }
  uint16_t *qtype_ptr = (uint16_t *)(query_ptr + 1);
  name_query->type = ntohs(*qtype_ptr);
  uint16_t *qclass_ptr = (uint16_t *)(query_ptr + 3);
  name_query->qclass = ntohs(*qclass_ptr);
}

size_t prepare_response(struct dns_query *name_query, unsigned char *buffer,
                        size_t num_received, uint32_t ttl, char *ip) {
  struct dns_header *header = (struct dns_header *)buffer;
  header->qr = 1;
  header->aa = 0;
  header->tc = 0;
  header->ra = 0;
  switch (name_query->type) {
  case QTYPE_A:
    header->rcode = RESPONSE_SUCCESS;
    header->ancount = htons(1);
    break;
  case QTYPE_AAAA:
    header->rcode = RESPONSE_SUCCESS;
    header->ancount = 0;
    break;
  default:
    header->rcode = RESPONSE_REFUSED;
    header->ancount = 0;
    break;
  }
  header->nscount = 0;
  header->arcount = 0;
  size_t response_length =
      name_query->type == 1 ? num_received + 18 : num_received;
  if (name_query->type == 1) {
    struct dns_response_trailer *trailer =
        (struct dns_response_trailer *)(buffer + num_received);
    trailer->ans_type = 0xc0; // pointer
    trailer->name_offset = 0x0c;
    trailer->type = htons(QTYPE_A);
    trailer->qclass = htons(QCLASS_INET);
    trailer->ttl = htonl(ttl);
    trailer->rdlength = htons(4);
    inet_pton(AF_INET, ip, &trailer->rdata);
  }
  return response_length;
}