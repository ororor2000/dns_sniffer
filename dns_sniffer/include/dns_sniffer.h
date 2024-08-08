#ifndef __DNS_SNIFFER_H__
#define __DNS_SNIFFER_H__

#include <stdint.h>
#include <stdio.h>

#define BUFFER_SIZE 4096
#define DNS_PORT 53

#define IP_VERSION_MASK 0x0f
#define MAX_PKT_SIZE 0xffff

#define IPV4_DNS_PAYLOAD_OFFSET 28
#define IPV6_DNS_PAYLOAD_OFFSET 48

#define LOG_FILE_PATH "/tmp/dns_sniffer.log"
#define LOG_FILE_MODE "a"

#define MAX_LINE_SIZE 1024
#define DOMAIN_MAX_SIZE 256
#define IP_MAX_SIZE 40  // using ipv6 size

#define DST_IPV4_OFFSET 16
#define DST_IPV6_OFFSET 24

enum dns_pkt_qtype_t {
    A = 1,
    AAAA = 28,
    CNAME = 5,
    OTHER = -1
};

enum dns_pkt_ip_version_t {
    IPV4 = 4,
    IPV6 = 6
};

enum dns_sniffer_exit_status_t {
    DS_NFLOG_OPEN_ERROR_EXIT_CODE = -9,
    DS_NFLOG_UNBINDING_PF_ERROR_EXIT_CODE = -8,
    DS_NFLOG_BINDING_PF_ERROR_EXIT_CODE = -7,
    DS_NFLOG_BIND_GROUP_ERROR_EXIT_CODE = -6,
    DS_NFLOG_SET_MODE_ERROR_EXIT_CODE = -5,
    DS_NFLOG_REGISTER_CALLBACK_ERROR_EXIT_CODE = -4,
    DS_NFLOG_OPEN_FD_ERROR_EXIT_CODE = -3,
    DS_GENERAL_FAILURE_EXIT_CODE = -2,
    DS_SIGNAL_INTERRUPT_EXIT_CODE = -1,
    DS_SUCCESS_EXIT_CODE = 0
};

struct dns_response_t {
    enum dns_pkt_qtype_t query_type;
    enum dns_pkt_ip_version_t ip_version;
    char dns_server[IP_MAX_SIZE];
    char domain[DOMAIN_MAX_SIZE];
};

struct dns_callback_data_t {
    void (*callback)(struct dns_response_t *response, FILE *output_fd);
    FILE *output_fd;
};

struct dns_sniffer_t {
    struct nflog_handle *nflog_handle;
    struct nflog_g_handle *nflog_group_handle;
    int should_exit;
};

// enum dns_sniffer_exit_status_t _init_dns_sniffer(struct dns_sniffer_t *sniffer, uint16_t nflog_group);

// void parse_domain(const char *dns_payload, int dns_payload_len, struct dns_response_t *out, int *seek);

// void parse_query_type(char *dns_payload, int question_start, struct dns_response_t *out);

// void parse_dns_packet(char *payload, int payload_len, struct dns_response_t *out);

// int cb_handle_dns_packet(struct nflog_g_handle_t *group_handle, struct nfgenmsg_t *nfmsg, struct nflog_data_t *nfa, void *data);

// enum dns_sniffer_exit_status_t _register_packet_handler(struct dns_sniffer_t *sniffer, struct dns_callback_data_t *callback_data);

// enum dns_sniffer_exit_status_t _start_dns_sniffer(struct dns_sniffer_t *sniffer);

enum dns_sniffer_exit_status_t start_dns_sniffer(struct dns_sniffer_t *sniffer, struct dns_callback_data_t *callback_data, uint16_t nflog_group);

void close_dns_sniffer(struct dns_sniffer_t *sniffer);

#endif