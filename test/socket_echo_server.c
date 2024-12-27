#include <stdio.h>
#include <lwip/opt.h>
#include <lwip/sockets.h>
#include <unistd.h>
#include "lwip.h"

#define BUFFER_SIZE 4096
#define on_error(...)                 \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        fflush(stderr);               \
    } while(0);

char buf[BUFFER_SIZE];
void *socket_echo_server (char *argv) {
    int port = TCP_LOCAL_SERVER_PORT;

    int server_fd, client_fd, err;
    struct sockaddr_in server, client;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) on_error("Could not create socket\n");

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = htonl(INADDR_ANY);

    int opt_val = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof opt_val);

    err = bind(server_fd, (struct sockaddr *) &server, sizeof(server));
    if (err < 0) on_error("Could not bind socket\n");

    err = listen(server_fd, 128);
    if (err < 0) on_error("Could not listen on socket\n");

    printf("Server is listening on %d\n", port);

    while (1) {
        socklen_t client_len = sizeof(client);
        client_fd = accept(server_fd, (struct sockaddr *) &client, &client_len);

        if (client_fd < 0) on_error("Could not establish new connection\n");

        while (1) {
            int read = recv(client_fd, buf, BUFFER_SIZE, 0);

            if (read == 0) {
                on_error("socket echo server: no data\n");
                continue; // done reading
            }
            if (read < 0) {
                on_error("socket echo server: read failed\n");
                close(client_fd);
                break;
	    }

            err = send(client_fd, buf, read, 0);
            if (err < 0) {
                on_error("socket echo server: write failed\n");
                close(client_fd);
                break;
	    }
        }
    }

    // never reach here
    return NULL;
}

int create_socket_echo_server(void) {
    sys_thread_t st = NULL;
    st = sys_thread_new("socket echo server", socket_echo_server, NULL, 4096, 1);
    if (st == NULL)
    {
        return -1;
    }
    return 0;
}
