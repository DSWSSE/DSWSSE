#ifndef SERVER_H
#define SERVER_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <netinet/in.h>
#include <unistd.h>
#include <hiredis/hiredis.h>

class Server {
public:
    Server();
    ~Server();
    void start();

private:
    void handleClient(int client_socket);
    void flushDatabase();
    void closeConnection();

    int server_socket;
    redisContext* database;
    bool running;
};

#endif // SERVER_H

