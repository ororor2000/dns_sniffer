#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "dns_sniffer.h"
#include "firewall.h"

#define IPV4 4
#define IPV6 6

#define NFLOG_GROUP 3

#define SUCCESS_EXIT 0
#define FAILURE_EXIT 1

static struct dns_sniffer_t g_sniffer = {0};
static struct dns_callback_data_t g_callback_data = {0};

void cleanup() {
    printf("Cleaning up...\n");
    delete_output_dns_nflog_rule(IPV4, NFLOG_GROUP);
    delete_output_dns_nflog_rule(IPV6, NFLOG_GROUP);

    close_dns_sniffer(&g_sniffer);

    if (g_callback_data.output_fd) {
        fclose(g_callback_data.output_fd);
        g_callback_data.output_fd = NULL;
    }
}

void setup_iptables_rules() {
    /* removing any existing rules from previous runs */
    delete_output_dns_nflog_rule(IPV4, NFLOG_GROUP);
    delete_output_dns_nflog_rule(IPV6, NFLOG_GROUP);

    add_output_dns_nflog_rule(IPV4, NFLOG_GROUP);
    add_output_dns_nflog_rule(IPV6, NFLOG_GROUP);
}

void cb_print_dns_packet(struct dns_response_t *response, FILE *output_fd) {
    char timestamp[20];
    time_t now = time(NULL);
    struct tm *local = localtime(&now);

    strftime(timestamp, sizeof(timestamp), "%d-%m-%Y %H:%M:%S", local);
    printf("%s | Server: %s, Domain: %s, IP Version: %s, Query Type: %s\n",
           timestamp,
           response->dns_server,
           response->domain,
           (response->ip_version == IPV4) ? "IPv4" : "IPv6",
           (response->query_type == A) ? "A" : (response->query_type == AAAA) ? "AAAA"
                                           : (response->query_type == CNAME)  ? "CNAME"
                                                                              : "Unknown");
    fprintf(output_fd, "%s | Server: %s, Domain: %s, IP Version: %s, Query Type: %s\n",
            timestamp,
            response->dns_server,
            response->domain,
            (response->ip_version == IPV4) ? "IPv4" : "IPv6",
            (response->query_type == A) ? "A" : (response->query_type == AAAA) ? "AAAA"
                                            : (response->query_type == CNAME)  ? "CNAME"
                                                                               : "Unknown");
}

void signal_handler(int signum) {
    g_sniffer.should_exit = 1;
    printf("got signal %d\n", signum);
}

enum dns_sniffer_exit_status_t exit_code;
int main() {
    int return_code;

    return_code = SUCCESS_EXIT;

    printf("Setting up signal handlers\n");
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("opening log file\n");
    g_callback_data.output_fd = fopen(LOG_FILE_PATH, LOG_FILE_MODE);
    if (!g_callback_data.output_fd) {
        printf("Error opening log file\n");
        return_code = FAILURE_EXIT;
        goto cleanup;
    }

    printf("Setting up iptables rules\n");
    setup_iptables_rules();

    printf("Initializing DNS sniffer\n");
    g_callback_data.callback = cb_print_dns_packet;
    exit_code = start_dns_sniffer(&g_sniffer, &g_callback_data, NFLOG_GROUP);
    if (exit_code < DS_SIGNAL_INTERRUPT_EXIT_CODE) {
        printf("Failed to initialize sniffer, exit code: %d\n", exit_code);
        return_code = FAILURE_EXIT;
        goto cleanup;
    }

    if (exit_code == DS_SIGNAL_INTERRUPT_EXIT_CODE) {
        printf("Received interrupt signal\n");
    }

cleanup:
    cleanup();
    printf("Exiting with code: %d\n", return_code);
    return return_code;
}