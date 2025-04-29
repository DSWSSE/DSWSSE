#ifndef CLIENT_H
#define CLIENT_H
#include <unordered_map>
#include <vector>
#include <set>
#include <string>
#include <random>
#include <iostream>
#include "Crypto.h"
#include "Document.h"
#include "Index.h"
#include "Timer.h"
#include "StashMonitor.h"
#include "KeywordsComparator.h"
#include <fstream>
#include <stdexcept>
#include <boost/asio.hpp>
using boost::asio::ip::tcp;
using namespace std;

class Client {
private:
    static const int DOCUMENT_SIZE = 1024;
    static constexpr double Document_Expansion = 1;
    
    vector<unsigned char> key;
    vector<unsigned char> signingKey;
    vector<int> array_counter;
    unordered_map<string, int> keyword_count;
    unordered_map<string, int> keyword_max;
    unordered_map<string, int> keyword_query_counter;
    unordered_map<string, int> keyword_insert_counter;
    int document_identifier_counter;
    unordered_map<string, Index> lookup_stash1; 
    unordered_map<string, int> lookup_stash2;
    unordered_map<int, Document> document_stash;
    set<int> array_loc_stash; 
    void initializeSocket(unordered_map<string, string>& configuration);
    void initializeFileStreams(unordered_map<string, string>& configuration);
    
public:
    Client(unordered_map<string, string>& configuration);
    ~Client();
    void initialise(std::vector<Document>& documents, const std::unordered_map<std::string, std::string>& configuration);
    void setup(std::vector<Document>& documents, const std::unordered_map<std::string, std::string>& configuration, Timer& timer_setup, int client_socket);
    static std::string bytesToHex(const std::vector<unsigned char>& bytes);
    void single_keyword_query(const std::string& keyword, std::mt19937& random, Timer& timer_query, Timer& timer_write_back, StashMonitor& stashMonitor);
    int insertion_query(const Document& document, std::mt19937& random, Timer& timer_query, Timer& timer_write_back, StashMonitor& stashMonitor);
    std::unordered_map<std::string, int> get_keywords();
    static std::unordered_map<std::string, std::string> parse_configuration(const std::string& filename_input);
    vector<int> generateRandomNumbers(const unordered_map<string, string>& configuration);
    void DocumentDataSearch(const std::vector<Document>& documents, const std::vector<int>& randomNumbers, const unordered_map<string, string>& configuration, int client_socket); 
    void write_back(size_t array_loc, const std::string& decrypted_value, int client_socket, bool send_command = true);
    void updateDocumentCounter(size_t array_loc);
    
    
    void write_back_from_stash(int client_socket, double selection_ratio);
    void add_to_stash(int doc_id, const Document& doc);
    Document get_from_stash(int doc_id);
    bool remove_from_stash(int doc_id);
    size_t get_stash_document_count() const;
    int get_stash_size();
    

    
};
#endif // CLIENT_H