#include <iostream>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <random>
#include "Client.h"
#include "Timer.h"
#include "StashMonitor.h"
#include "Parser.h"
#include <sstream>
using namespace std;

void single_keyword_query_test(unordered_map<string, string>& configuration, int client_socket);

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <configuration file>" << endl;
        return 1;
    }
    
    unordered_map<string, string> configuration = Client::parse_configuration(argv[1]);
    int port = stoi(configuration.at("port"));
    
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to connect to server");
        exit(EXIT_FAILURE);
    }
    
    cout << "Successfully connected to server!" << endl;
    
    if (configuration["mode"] == "search") {
        single_keyword_query_test(configuration, client_socket);
    }
    
    return 0;
}

void single_keyword_query_test(unordered_map<string, string>& configuration, int client_socket) {
    vector<Document> documents;
    Parser::parse_documents(documents, configuration);
    cout << "Read done." << endl;
    
    Client client(configuration);
    cout << "Before initialise: documents.size() = " << documents.size() << endl;
    client.initialise(documents, configuration);
    cout << "After initialise: documents.size() = " << documents.size() << endl;
    
    int keyword_document_pair_count = 0;
    for (auto& document : documents) {
        keyword_document_pair_count += document.get_keywords().size();
    }
    
    int document_size = 0;
    for (auto& document : documents) {
        document_size += document.get_size() + 28;
    }
    
    Timer timer_setup;
    client.setup(documents, configuration, timer_setup, client_socket);
    documents.clear();
    cout << "Setup done." << endl;
    
    Timer loopTimer; 
    int query_count = 0;
    int total_queries = std::stoi(configuration.at("N_queries"));
    
    for (int idx = 0; idx < total_queries; idx++) {
        loopTimer.start();  
        vector<int> randomNumbers = client.generateRandomNumbers(configuration);
        client.DocumentDataSearch(documents, randomNumbers, configuration, client_socket);
        loopTimer.stop();  
    }
        
    double total_time = static_cast<double>(loopTimer.get_total_time());  
    double average_time = (total_time / total_queries) / 1e6;  
    std::cout << "Average loop time: " << average_time << " ms" << std::endl;
}