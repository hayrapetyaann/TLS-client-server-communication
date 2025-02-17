#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT 4433
#define SERVER_IP "127.0.0.1"
#define BUFFER_SIZE 1024

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    struct sockaddr_in addr;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        handle_errors();
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("SSL connection established\n");

        char buffer[BUFFER_SIZE];
        while (1) {
            printf("Enter message to send: ");
            fgets(buffer, sizeof(buffer), stdin);
            if (strncmp(buffer, "exit", 4) == 0) {
                break;
            }
            SSL_write(ssl, buffer, strlen(buffer));

            int bytes = SSL_read(ssl, buffer, sizeof(buffer));
            if (bytes > 0) {
                buffer[bytes] = '\0'; 
                printf("Received from server: %s\n", buffer);
            } else {
                printf("Server disconnected.\n");
                break;
            }
        }
    }

    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}
