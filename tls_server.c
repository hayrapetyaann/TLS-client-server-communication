#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define PORT 4433
#define BUFFER_SIZE 1024

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        handle_errors();
    }

    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        handle_errors();
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        handle_errors();
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 1) == -1) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    int client_fd = accept(server_fd, (struct sockaddr*)&addr, &len);
    if (client_fd == -1) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("SSL connection established\n");

        char buffer[BUFFER_SIZE];
        while (1) {
            int bytes = SSL_read(ssl, buffer, sizeof(buffer));
            if (bytes > 0) {
                buffer[bytes] = '\0'; 
                printf("Received: %s\n", buffer);
                if (strncmp(buffer, "exit", 4) == 0) {
                    break;
                }
            }

            printf("Enter message to send: ");
            fgets(buffer, sizeof(buffer), stdin);
            if (strncmp(buffer, "exit", 4) == 0) {
                break;
            }
            SSL_write(ssl, buffer, strlen(buffer));
        }
    }

    SSL_free(ssl);
    close(client_fd);
    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}

