#include "Client.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <random>
#include <filesystem>
#include <vector>
#include <string>
#include "Crypto.h"
#include <unordered_map>
#include <unordered_set>
#include <cstdlib>
#include <ctime>
#include <arpa/inet.h>
#include <chrono>
#include <thread>

using namespace std;
namespace fs = filesystem;

Client::Client(unordered_map<string, string>& configuration) {
    int port = stoi(configuration.at("port"));
}

Client::~Client() {
    try {
        // Nothing to do here after removing debug message
    } catch (...) {
        // Error handling removed
    }
}

void Client::initialise(vector<Document>& documents, const unordered_map<string, string>& configuration) {
    this->key = Crypto::key_gen();
    this->signingKey = this->key;
    
    std::vector<Document> processed_documents;
    
    for (const Document& doc : documents) {
        if (doc.check_size(DOCUMENT_SIZE)) {
            std::vector<Document> split_docs = doc.split(DOCUMENT_SIZE);
            processed_documents.insert(processed_documents.end(), 
                                    split_docs.begin(), 
                                    split_docs.end());
        } else {
            processed_documents.push_back(doc);
        }
    }
    
    documents = std::move(processed_documents);

    unordered_map<string, int> keyword_current;
    for (auto& document : documents) {
        auto keywords = document.get_keywords();
        for (size_t ii = 0; ii < keywords.size(); ++ii) {
            const auto& keyword = keywords[ii];
            keyword_count[keyword]++;
            if (keyword_query_counter.find(keyword) == keyword_query_counter.end()) {
                keyword_query_counter[keyword] = 0;
            }
            if (keyword_insert_counter.find(keyword) == keyword_insert_counter.end()) {
                keyword_insert_counter[keyword] = 0;
            }
            keyword_current[keyword]++;
            document.set_keyword_counter(ii, keyword_current[keyword]);
        }
    }

    int Keyword_Expansion = 1;

    vector<string> keywords;
    for (const auto& pair : keyword_count) {
        keywords.push_back(pair.first);
    }
    sort(keywords.begin(), keywords.end(), [this](const string& a, const string& b) {
        return keyword_count[a] > keyword_count[b];
    });

    int group_size_large = stoi(configuration.at("Group_size_large"));
    int group_size_small = stoi(configuration.at("Group_size_small"));

    unordered_map<string, pair<int, int>> keyword_group_info;  

    int offset = group_size_large * 6;
    for (int ii = 0; ii < 6; ++ii) {
        int count_max = keyword_count[keywords[ii * group_size_large]];
        for (int jj = ii * group_size_large; jj < min((ii + 1) * group_size_large, static_cast<int>(keywords.size())); ++jj) {
            count_max = max(count_max, keyword_count[keywords[jj]]);
        }
        for (int jj = ii * group_size_large; jj < min((ii + 1) * group_size_large, static_cast<int>(keywords.size())); ++jj) {
            keyword_max[keywords[jj]] = count_max * Keyword_Expansion;
            keyword_group_info[keywords[jj]] = {ii, count_max};  
        }
    }

    for (int ii = 0; ii < ceil((keywords.size() - offset) / static_cast<double>(group_size_small)); ++ii) {
        int count_max = keyword_count[keywords[offset + ii * group_size_small]];
        for (int jj = offset + ii * group_size_small; jj < min(offset + (ii + 1) * group_size_small, static_cast<int>(keywords.size())); ++jj) {
            count_max = max(count_max, keyword_count[keywords[jj]]);
        }
        for (int jj = offset + ii * group_size_small; jj < min(offset + (ii + 1) * group_size_small, static_cast<int>(keywords.size())); ++jj) {
            keyword_max[keywords[jj]] = count_max * Keyword_Expansion;
            keyword_group_info[keywords[jj]] = {ii + 6, count_max};  
        }
    }

    array_counter.resize(static_cast<int>(documents.size() * Document_Expansion), 0);
    document_identifier_counter = static_cast<int>(documents.size() * Document_Expansion);
}

void Client::setup(vector<Document>& documents, const unordered_map<string, string>& configuration, Timer& timer_setup, int client_socket) {
    timer_setup.start();
    mt19937 random;

    int command = 1;
    send(client_socket, &command, sizeof(command), 0);

    for (size_t array_loc = 0; array_loc < documents.size();) {
        auto doc_address = Crypto::SHA256(signingKey, to_string(array_loc) + '-' + to_string(array_counter[array_loc]));
        
        int doc_address_size = static_cast<int>(doc_address.size());
        send(client_socket, &doc_address_size, sizeof(doc_address_size), 0);
        send(client_socket, doc_address.data(), doc_address.size(), 0);
        
        auto document_data = documents[array_loc].get_string(DOCUMENT_SIZE);
        auto document_data_enc = Crypto::GCM_encrypt(key, document_data);
        
        int doc_data_enc_size = static_cast<int>(document_data_enc.size());
        send(client_socket, &doc_data_enc_size, sizeof(doc_data_enc_size), 0);
        send(client_socket, document_data_enc.data(), document_data_enc.size(), 0);
        
        array_loc += 1;
    }

    int end_signal = -1;
    send(client_socket, &end_signal, sizeof(end_signal), 0);

    int server_response;
    recv(client_socket, &server_response, sizeof(server_response), 0);

    timer_setup.stop();
}

unordered_map<string, string> Client::parse_configuration(const string& filename_input) {
    unordered_map<string, string> configuration;
    ifstream fp(filename_input);

    if (!fp.is_open()) {
        return configuration;
    }

    string next_line;
    while (getline(fp, next_line)) {
        size_t delimiter_pos = next_line.find(" = ");
        if (delimiter_pos != string::npos) {
            string key = next_line.substr(0, delimiter_pos);
            string value = next_line.substr(delimiter_pos + 3);
            configuration[key] = value;
        }
    }

    fp.close();
    return configuration;
}

vector<int> Client::generateRandomNumbers(const unordered_map<string, string>& configuration) {
    vector<int> randomNumbers;
    random_device rd;
    mt19937 gen(rd());
    
    vector<string> all_keywords;
    for (const auto& pair : keyword_count) {
        all_keywords.push_back(pair.first);
    }
    
    uniform_int_distribution<> key_dist(0, all_keywords.size() - 1);
    string selected_keyword = all_keywords[key_dist(gen)];
    
    int max_count = keyword_max[selected_keyword]; 
    
    int num_docs_to_retrieve = max(10, max_count);
    
    uniform_int_distribution<> doc_dist(0, array_counter.size() - 1);
    
    unordered_set<int> selected_indices;
    while (selected_indices.size() < num_docs_to_retrieve) {
        int index = doc_dist(gen);
        selected_indices.insert(index);
    }
    
    randomNumbers.assign(selected_indices.begin(), selected_indices.end());
    
    return randomNumbers;
}

void Client::DocumentDataSearch(const vector<Document>& documents, const vector<int>& randomNumbers, const unordered_map<string, string>& configuration, int client_socket) {
    Timer retrievalTimer;
    int successfulDecryptions = 0;
    
    int command = 0;
    send(client_socket, &command, sizeof(command), 0);

    document_stash.clear();
    array_loc_stash.clear();

    retrievalTimer.start();

    for (size_t array_loc : randomNumbers) {
        if (array_loc < 0 || array_loc >= array_counter.size()) {
            continue;
        }

        auto doc_address = Crypto::SHA256(signingKey, to_string(array_loc) + '-' + to_string(array_counter[array_loc]));

        int doc_address_size = static_cast<int>(doc_address.size());
        send(client_socket, &doc_address_size, sizeof(doc_address_size), 0);
        send(client_socket, doc_address.data(), doc_address.size(), 0);
        
        int value_size;
        if (recv(client_socket, &value_size, sizeof(value_size), 0) > 0) {
            if (value_size > 0) {
                vector<unsigned char> encrypted_value(value_size);
                
                size_t total_received = 0;
                while (total_received < value_size) {
                    ssize_t received = recv(client_socket, 
                                        encrypted_value.data() + total_received,
                                        value_size - total_received, 
                                        0);
                    if (received <= 0) {
                        break;
                    }
                    total_received += received;
                }

                if (total_received == value_size) {
                    try {
                        string decrypted_value = Crypto::GCM_decryption(key, encrypted_value);
                        successfulDecryptions++;
                        
                        vector<string> dummy_keywords = {"retrieved"};
                        Document doc(decrypted_value, "retrieved", DOCUMENT_SIZE);
                        document_stash[document_identifier_counter] = doc;
                        array_loc_stash.insert(array_loc);
                        document_identifier_counter++;

                    } catch (const runtime_error& e) {
                        // Decryption error handled silently
                    }
                }
            } else {
                char empty_value;
                recv(client_socket, &empty_value, 1, 0);
            }
        }
    }

    retrievalTimer.stop();
    
    int end_signal = -1;
    send(client_socket, &end_signal, sizeof(end_signal), 0);

    int server_response;
    recv(client_socket, &server_response, sizeof(server_response), 0);

    Timer updateTimer;
    updateTimer.start();
    
    write_back_from_stash(client_socket, 0.5);
    
    updateTimer.stop();
    
    send(client_socket, &end_signal, sizeof(end_signal), 0);
    recv(client_socket, &server_response, sizeof(server_response), 0);
}

void Client::write_back(size_t array_loc, const std::string& decrypted_value, int client_socket, bool send_command) {
    if (send_command) {
        int command = 1;
        send(client_socket, &command, sizeof(command), 0);
    }
    
    auto updated_doc_address = Crypto::SHA256(signingKey, to_string(array_loc) + '-' + to_string(array_counter[array_loc] + 1));
    
    auto updated_doc_data_enc = Crypto::GCM_encrypt(key, decrypted_value);

    array_counter[array_loc] += 1; 

    int updated_doc_address_size = static_cast<int>(updated_doc_address.size());
    send(client_socket, &updated_doc_address_size, sizeof(updated_doc_address_size), 0);
    send(client_socket, updated_doc_address.data(), updated_doc_address.size(), 0);

    int updated_doc_data_enc_size = static_cast<int>(updated_doc_data_enc.size());
    send(client_socket, &updated_doc_data_enc_size, sizeof(updated_doc_data_enc_size), 0);
    send(client_socket, updated_doc_data_enc.data(), updated_doc_data_enc.size(), 0);
}

void Client::write_back_from_stash(int client_socket, double selection_ratio) {
    if (document_stash.empty()) {
        return;
    }
    
    vector<int> doc_ids;
    for (const auto& pair : document_stash) {
        doc_ids.push_back(pair.first);
    }
    
    random_device rd;
    mt19937 g(rd());
    shuffle(doc_ids.begin(), doc_ids.end(), g);
    
    size_t num_to_write = max(1UL, static_cast<size_t>(doc_ids.size() * selection_ratio));
    num_to_write = min(num_to_write, doc_ids.size());
    
    int update_command = 1;
    send(client_socket, &update_command, sizeof(update_command), 0);
    
    size_t written_count = 0;
    for (size_t i = 0; i < num_to_write && !array_loc_stash.empty(); ++i) {
        int doc_id = doc_ids[i];
        Document& doc = document_stash[doc_id];
        
        auto it = array_loc_stash.begin();
        int array_loc = *it;
        array_loc_stash.erase(it);
        
        string doc_data = doc.get_string(DOCUMENT_SIZE);
        write_back(array_loc, doc_data, client_socket, false);
        
        document_stash.erase(doc_id);
        written_count++;
    }
}

void Client::add_to_stash(int doc_id, const Document& doc) {
    document_stash[doc_id] = doc;
}

Document Client::get_from_stash(int doc_id) {
    if (document_stash.find(doc_id) != document_stash.end()) {
        return document_stash[doc_id];
    }
    vector<string> empty_keywords;
    return Document(empty_keywords, false, "");
}

bool Client::remove_from_stash(int doc_id) {
    if (document_stash.find(doc_id) != document_stash.end()) {
        document_stash.erase(doc_id);
        return true;
    }
    return false;
}

size_t Client::get_stash_document_count() const {
    return document_stash.size();
}

int Client::get_stash_size() {
    int stash_size = 0;
    
    for (const auto& [keyword, index] : lookup_stash1) {
        stash_size += keyword.length() + 4;
    }
    
    for (const auto& [keyword, idx] : lookup_stash2) {
        stash_size += keyword.length() + 2;
    }
    
    for (const auto& [idx, doc] : document_stash) {
        stash_size += 2 + doc.get_size();
    }
    
    return stash_size;
}