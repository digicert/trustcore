#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080

void send_file(FILE *fp, int sockfd) {
    char data[1024];
    size_t bytes_read;

    while ((bytes_read = fread(data, 1, sizeof(data), fp)) > 0) {
        if (send(sockfd, data, bytes_read, 0) == -1) {
            perror("Error sending file");
            exit(1);
        }
    }
}

int main(int argc, char *argv[]) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    FILE *fp;
    int toggle = 0;
    int count = 0;
    char cmd[32];
    int cmdLen = 32;


    char *pBootstrap = NULL;
    char *pFileSys = NULL;

    if (argc != 5) {
        printf("usage: ./my_tcp_server --bootstrap /path/to/zip --filesys /path/to/zip\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bootstrap") == 0 && i + 1 < argc) {
            pBootstrap = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--filesys") == 0 && i + 1 < argc) {
            pFileSys = argv[i + 1];
            i++;
        }
    }

    if (pBootstrap != NULL) {
        printf("Bootstrap path: %s\n", pBootstrap);
    } else {
        printf("Bootstrap path not provided.\n");
    }

    if (pFileSys != NULL) {
        printf("File path: %s\n", pFileSys);
    } else {
        printf("File path not provided.\n");
    }


    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Bind socket to port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %d\n", PORT);

    while (1) {
        // Accept incoming connection
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            close(server_fd);
            exit(EXIT_FAILURE);
        }
        count++;

        int valread = recv(new_socket, cmd, cmdLen, 0);
        if (valread <= 0) {
            close(new_socket);
            continue;
        }

        cmd[valread] = '\0';
        printf("cmd: %s\n", cmd);
        if (0 == strcmp(cmd, "bootstrap"))
        {
            fp = fopen(pBootstrap, "rb");
            printf("sending %s\n", pBootstrap);

        } else if (0 == strcmp(cmd, "filesys"))
        {
            fp = fopen(pFileSys, "rb");
            printf("sending %s\n", pFileSys);
        }

#if 0
        // Toggle between files
        if (toggle == 0) {
            fp = fopen(pFileSys, "rb");
            printf("sending %s\n", pFileSys);
            toggle = 1;
        } else {
            fp = fopen(pBootstrap, "rb");
            printf("sending %s\n", pBootstrap);
            toggle = 0;
        }
#endif

        if (fp == NULL) {
            perror("File not found");
            close(new_socket);
            continue;
        }

        // Send file to client
        send_file(fp, new_socket);
        printf("File sent successfully\n");

        // Close file and socket
        fclose(fp);
        close(new_socket);
    }

    close(server_fd);
    return 0;
}

