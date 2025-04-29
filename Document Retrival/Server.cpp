#include <iostream>
#include <unordered_map>
#include <vector>
#include <cstring>
#include <string>
#include <netinet/in.h>
#include <unistd.h>
#include <hiredis/hiredis.h>
//#include "Timer.h"

using namespace std;

class Server {
public:
    void start() {
        int server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket < 0) {
            perror("Socket creation failed");
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(59090);
        server_addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            perror("Bind failed");
            close(server_socket);
            exit(EXIT_FAILURE);
        }

        if (listen(server_socket, 5) < 0) {
            perror("Listen failed");
            close(server_socket);
            exit(EXIT_FAILURE);
        }

        cout << "The server is running..." << endl;

        redisContext* database = redisConnect("127.0.0.1", 6379);
        if (database == nullptr || database->err) {
            exit(EXIT_FAILURE);
        }
        redisCommand(database, "FLUSHALL");

        bool run = true;
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);

        if (client_socket < 0) {
            perror("Accept failed");
            close(server_socket);
            return;
        }

        while (run) {
            int operation;
            ssize_t bytes_received = recv(client_socket, &operation, sizeof(operation), 0);
            if (bytes_received < 0) {
                
            }
            else if(bytes_received == 0){
                run = false;
                close(client_socket);
            }
            else{
                if (operation == 0) {
                    processGetOperation(client_socket, database);
                } else if (operation == 1) {
                    processSetOperation(client_socket, database);
                } else if (operation == 2) {
                    processNewInstance(client_socket, database);
                } else if (operation == 3) {
                    run = false;
                    close(client_socket);
                }
            }
        }

        redisFree(database);
        close(server_socket);
    }

private:
    void processGetOperation(int client_socket, redisContext* database) {
        int doc_address_size_network;
        while (true) {
            int received = recv(client_socket, &doc_address_size_network, sizeof(doc_address_size_network), 0);
            int doc_address_size = doc_address_size_network;

            
            if (doc_address_size <= 0) {
                break;  
            }
            
            vector<unsigned char> doc_address(doc_address_size);
            received = recv(client_socket, doc_address.data(), doc_address_size, 0);
            
            redisReply* size_reply = (redisReply*)redisCommand(
                database, 
                "STRLEN %b", 
                doc_address.data(),
                doc_address_size
            );
            if (size_reply != nullptr) {
                freeReplyObject(size_reply);
            }

            redisReply* reply = (redisReply*)redisCommand(
                database, 
                "GET %b", 
                doc_address.data(),
                doc_address_size
            );

            if (reply == nullptr) {
                break;
            }

            if (reply->type == REDIS_REPLY_STRING) {
                vector<unsigned char> value(reply->str, reply->str + reply->len);

                int value_size = static_cast<int>(value.size());
                int value_size_network = value_size;
                
                send(client_socket, &value_size_network, sizeof(value_size_network), 0);
                
                size_t total_sent = 0;
                while (total_sent < value.size()) {
                    ssize_t sent = send(client_socket, 
                                    value.data() + total_sent,
                                    value.size() - total_sent, 
                                    0);
                    if (sent <= 0) {
                        break;
                    }
                    total_sent += sent;
                }
            } else {
                int empty_size = 1;
                char empty_value = '\0';
                send(client_socket, &empty_size, sizeof(empty_size), 0);
                send(client_socket, &empty_value, 1, 0);
            }
            freeReplyObject(reply);
        }

        int response = 0;
        send(client_socket, &response, sizeof(response), 0);
    }

    void printHex(const vector<char>& data) {
        for (char c : data) {
            printf("%02x ", (unsigned char)c);
        }
        printf("\n");
    }

    void processSetOperation(int client_socket, redisContext* database) {
        int size;
        while (recv(client_socket, &size, sizeof(size), 0) > 0 && size > 0) {
            vector<unsigned char> key(size);
            if (recv(client_socket, key.data(), size, 0) != size) {
                break;
            }

            if (recv(client_socket, &size, sizeof(size), 0) != sizeof(size)) {
                break;
            }

            vector<unsigned char> value(size);
            size_t total_received = 0;
            while (total_received < size_t(size)) {
                ssize_t received = recv(client_socket, 
                                    value.data() + total_received,
                                    size - total_received, 
                                    0);
                if (received <= 0) {
                    break;
                }
                total_received += received;
            }

            if (total_received != size_t(size)) {
                break;
            }

            redisReply* reply = (redisReply*)redisCommand(
                database, "SET %b %b", 
                key.data(), key.size(), 
                value.data(), value.size()
            );

            if (reply == nullptr) {
                break;
            } else {
                redisReply* verify_reply = (redisReply*)redisCommand(
                    database, "GET %b",
                    key.data(), key.size()
                );
                
                if (verify_reply != nullptr) {
                    freeReplyObject(verify_reply);
                }
            }
            freeReplyObject(reply);
        }
        
        int response = 0;
        send(client_socket, &response, sizeof(response), 0);
    }

    void processNewInstance(int client_socket, redisContext* database) {
        redisCommand(database, "FLUSHALL");
        int response = 0;
        send(client_socket, &response, sizeof(response), 0);
    }
};

int main() {
    Server server;
    server.start();
    return 0;
}