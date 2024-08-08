#include "dns_sniffer.h"

#include <arpa/inet.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static enum dns_sniffer_exit_status_t _init_dns_sniffer(struct dns_sniffer_t *dns_sniffer, uint16_t nflog_group) {
    dns_sniffer->nflog_handle = NULL;
    dns_sniffer->nflog_group_handle = NULL;

    dns_sniffer->nflog_handle = nflog_open();
    if (!dns_sniffer->nflog_handle)
        return DS_NFLOG_OPEN_ERROR_EXIT_CODE;

    int i, ip_versions[] = {AF_INET, AF_INET6};
    for (i = 0; i < 2; i++) {
        if (nflog_unbind_pf(dns_sniffer->nflog_handle, ip_versions[i]) < 0)
            return DS_NFLOG_UNBINDING_PF_ERROR_EXIT_CODE;
    }

    for (i = 0; i < 2; i++) {
        if (nflog_bind_pf(dns_sniffer->nflog_handle, ip_versions[i]) < 0)
            return DS_NFLOG_BINDING_PF_ERROR_EXIT_CODE;
    }

    dns_sniffer->nflog_group_handle = nflog_bind_group(dns_sniffer->nflog_handle, nflog_group);
    if (!dns_sniffer->nflog_group_handle)
        return DS_NFLOG_BIND_GROUP_ERROR_EXIT_CODE;

    if (nflog_set_mode(dns_sniffer->nflog_group_handle, NFULNL_COPY_PACKET, MAX_PKT_SIZE) < 0) {
        return DS_NFLOG_SET_MODE_ERROR_EXIT_CODE;
    }

    return DS_SUCCESS_EXIT_CODE;
}

static void parse_domain(const char *dns_payload, int dns_payload_len, struct dns_response_t *out, int *seek) {
    /*
        to make sure were not going out of bounds in `data`,
        if `data` is smaller or equal to the size of the dns header section
        we simply return
    */
    if (dns_payload_len <= 12) {
        return;
    }

    // starting after the dns header
    // at an offset of 12 bytes from the start
    int i = 12, char_index = 0;
    while (i < dns_payload_len) {
        int section_length = dns_payload[i];
        if (section_length == 0) {
            break;
        }

        /*
            An example for the domain section in the dns payload
            03 'w' 'w' 'w' 07 'e' 'x' 'a' 'm' 'p' 'l' 'e' 03 'c' 'o' 'm' 00
            each section is prefix with each length, followed by a '.'
            character so, ill fetch the length of the current section, then
            loop for this length and print each char
        */
        for (int j = 1; j <= section_length; j++) {
            out->domain[char_index++] = dns_payload[i + j];
        }

        // move to the next section in the domain
        i += section_length + 1;

        // only print '.' if the next section length is not 0 (the domain
        // end)
        if (dns_payload[i] != 0) {
            out->domain[char_index++] = '.';
        }
    }

    // setting seek at the end of domain/start of the question section (for query type parsing)
    *seek = i + 1;

    out->domain[char_index] = '\0';
}

static void parse_query_type(char *dns_payload, int question_start, struct dns_response_t *out) {
    /*
        the qtype field is 16 bit long, so ill be using an `uint16_t` field to
        fetch its value the field resides right
    */
    uint16_t qtype;
    memcpy(&qtype, (char *)(dns_payload + question_start), sizeof(uint16_t));

    out->query_type = (enum dns_pkt_qtype_t)ntohs(qtype);
}

static void parse_dns_packet(char *payload, int payload_len, struct dns_response_t *out) {
    int dns_payload_len, seek = 0;
    char *dns_payload;

    /*
        The DNS Header is the first 12 (and 8 for IPV6) bytes of the data
        so according the structure of the DNS packet,
        the src ip resides at an offset of 12/8 bytes after the start of the DNS
        packet
    */
    if (out->ip_version == IPV4) {
        inet_ntop(AF_INET, (char *)(payload + DST_IPV4_OFFSET), out->dns_server, INET_ADDRSTRLEN);

        if (payload_len < IPV4_DNS_PAYLOAD_OFFSET) {
            return;
        }

        dns_payload = (char *)(payload + IPV4_DNS_PAYLOAD_OFFSET);
        dns_payload_len = payload_len - IPV4_DNS_PAYLOAD_OFFSET;
    } else {  // IPV6
        inet_ntop(AF_INET6, (char *)(payload + DST_IPV6_OFFSET), out->dns_server, INET6_ADDRSTRLEN);

        if (payload_len < IPV6_DNS_PAYLOAD_OFFSET) {
            return;
        }

        dns_payload = (char *)(payload + IPV6_DNS_PAYLOAD_OFFSET);
        dns_payload_len = payload_len - IPV6_DNS_PAYLOAD_OFFSET;
    }

    parse_domain(dns_payload, dns_payload_len, out, &seek);
    parse_query_type(dns_payload, seek, out);
}

static int cb_handle_dns_packet(struct nflog_g_handle *group_handle, struct nfgenmsg *nfmsg, struct nflog_data *nfa, void *data) {
    (void)group_handle;

    struct dns_callback_data_t *callback_data = (struct dns_callback_data_t *)data;
    struct dns_response_t dns_response;
    char *payload;

    int payload_len = nflog_get_payload(nfa, &payload);
    if (payload_len < 0) {
        return DS_GENERAL_FAILURE_EXIT_CODE;
    }

    // Extract the IP version from the first byte of the IP header
    char ip_version = (payload[0] >> 4) & IP_VERSION_MASK;
    dns_response.ip_version = (enum dns_pkt_ip_version_t)ip_version;

    parse_dns_packet(payload, payload_len, &dns_response);

    callback_data->callback(&dns_response, callback_data->output_fd);
    return DS_SUCCESS_EXIT_CODE;
}

static enum dns_sniffer_exit_status_t _register_packet_handler(struct dns_sniffer_t *sniffer, struct dns_callback_data_t *callback_data) {
    if (nflog_callback_register(sniffer->nflog_group_handle, cb_handle_dns_packet, callback_data) < 0) {
        return DS_NFLOG_REGISTER_CALLBACK_ERROR_EXIT_CODE;
    }

    return DS_SUCCESS_EXIT_CODE;
}

static enum dns_sniffer_exit_status_t _start_dns_sniffer(struct dns_sniffer_t *sniffer) {
    int nflog_file_descriptor, rv;
    char buffer[BUFFER_SIZE];

    nflog_file_descriptor = nflog_fd(sniffer->nflog_handle);

    if (!nflog_file_descriptor) {
        return DS_NFLOG_OPEN_FD_ERROR_EXIT_CODE;
    }

    while ((rv = recv(nflog_file_descriptor, buffer, BUFFER_SIZE, 0)) && rv >= 0) {
        if (sniffer->should_exit) {
            return DS_SIGNAL_INTERRUPT_EXIT_CODE;
        }

        if (rv < 0) {
            continue;
        }

        if (nflog_handle_packet(sniffer->nflog_handle, buffer, rv) < 0) {
            continue;
        }
    }

    return DS_SUCCESS_EXIT_CODE;
}

enum dns_sniffer_exit_status_t start_dns_sniffer(struct dns_sniffer_t *sniffer, struct dns_callback_data_t *callback_data, uint16_t nflog_group) {
    enum dns_sniffer_exit_status_t exit_code;

    printf("initializing dns_sniffer\n");
    exit_code = _init_dns_sniffer(sniffer, nflog_group);
    if (exit_code != DS_SUCCESS_EXIT_CODE) {
        goto cleanup;
    }

    printf("registering callback function\n");
    exit_code = _register_packet_handler(sniffer, callback_data);
    if (exit_code != DS_SUCCESS_EXIT_CODE) {
        goto cleanup;
    }

    printf("runnning sniffer\n");
    exit_code = _start_dns_sniffer(sniffer);
    if (exit_code != DS_SUCCESS_EXIT_CODE) {
        goto cleanup;
    }

cleanup:
    close_dns_sniffer(sniffer);
    return exit_code;
}

void close_dns_sniffer(struct dns_sniffer_t *sniffer) {
    if (!sniffer) {
        return;
    }

    if (sniffer->nflog_group_handle) {
        nflog_unbind_group(sniffer->nflog_group_handle);
        sniffer->nflog_group_handle = NULL;
    }

    if (sniffer->nflog_handle) {
        nflog_close(sniffer->nflog_handle);
        sniffer->nflog_handle = NULL;
    }
}