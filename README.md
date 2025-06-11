# DNS Tunneling

This project implements a DNS tunneling system for data transfer through DNS queries, developed as part of the Network Applications and Network Administration (ISA) course.

- receiver
  - DNS receiver implementation
- sender
  - DNS sender implementation
- base32.c/h - Base32 encoding/decoding implementation
- dns.c/h - Core DNS protocol handling

- Makefile
- README.md

## Usage

Build code

```
Make
```

### Receiver

To run the DNS receiver:

```
./dns_receiver BASE_HOST DST_FILE
```

### Sender

To run the DNS sender:

```
./dns_sender [-u UPSTREAM_DNS] BASE_HOST DST_FILE [SRC_FILE]
```

- -u UPSTREAM_DNS : Optional upstream DNS server address
- BASE_HOST : Base domain name for DNS tunneling
- DST_FILE : Destination file name on receiver
- SRC_FILE : Source file to send (uses stdin if not specified)
