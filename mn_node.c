#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#pragma comment(lib, "ws2_32.lib")  // Link with Winsock library

#define PORT 8080
#define BUFFER_SIZE 1024

// Function to initialize Winsock
void initialize_winsock() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "Failed to initialize Winsock. Error: %d\n", WSAGetLastError());
        exit(EXIT_FAILURE);
    }
    printf("Winsock initialized.\n");
}

// Function to clean up Winsock
void cleanup_winsock() {
    WSACleanup();
}

// Function to initialize a socket
SOCKET initialize_socket() {
    SOCKET server_socket, client_socket;
    struct sockaddr_in address;
    int opt = 1;

    // Create socket
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed. Error: %d\n", WSAGetLastError());
        cleanup_winsock();
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        fprintf(stderr, "Setsockopt failed. Error: %d\n", WSAGetLastError());
        closesocket(server_socket);
        cleanup_winsock();
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind socket to port
    if (bind(server_socket, (struct sockaddr*)&address, sizeof(address)) == SOCKET_ERROR) {
        fprintf(stderr, "Bind failed. Error: %d\n", WSAGetLastError());
        closesocket(server_socket);
        cleanup_winsock();
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_socket, 3) == SOCKET_ERROR) {
        fprintf(stderr, "Listen failed. Error: %d\n", WSAGetLastError());
        closesocket(server_socket);
        cleanup_winsock();
        exit(EXIT_FAILURE);
    }

    printf("Mix Node listening on port %d...\n", PORT);

    // Accept a connection
    int addrlen = sizeof(address);
    if ((client_socket = accept(server_socket, (struct sockaddr*)&address, &addrlen)) == INVALID_SOCKET) {
        fprintf(stderr, "Accept failed. Error: %d\n", WSAGetLastError());
        closesocket(server_socket);
        cleanup_winsock();
        exit(EXIT_FAILURE);
    }

    closesocket(server_socket);  // Close the server socket as it's no longer needed
    return client_socket;
}

int main() {
    // Initialize Winsock
    initialize_winsock();

    // Initialize the socket and accept a connection
    SOCKET client_socket = initialize_socket();

    char buffer[BUFFER_SIZE];

    // Receive incoming message
    int bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
    if (bytes_received <= 0) {
        fprintf(stderr, "Receive failed. Error: %d\n", WSAGetLastError());
        closesocket(client_socket);
        cleanup_winsock();
        return -1;
    }

    printf("Received message (length: %d bytes):\n", bytes_received);
    buffer[bytes_received] = '\0';  // Null-terminate the buffer for printing

    printf("Data: %s\n", buffer);

    // Placeholder for additional functionality (like decryption and forwarding)
    printf("Processing received message...\n");

    // Cleanup
    closesocket(client_socket);
    cleanup_winsock();

    return 0;
}
