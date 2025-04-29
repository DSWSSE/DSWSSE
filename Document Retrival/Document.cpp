#include "Document.h"
#include <iostream>
#include <sstream>
#include <cmath>
#include <memory>   
#include <algorithm>
#include <vector>
#include <string>


Document::Document() : real(false) {
    std::vector<std::string> empty_keywords;
    keywords = empty_keywords;
    data = "";
    query_keyword = "";
}


Document::Document(const std::vector<std::string>& keywords, bool real, const std::string& data)
    : keywords(keywords), real(real), data(data) {}

Document::Document(const std::vector<std::string>& keywords)
    : keywords(keywords), real(false) {
    int keywords_len = 0;
    for (const auto& keyword : keywords) {
        keywords_len += keyword.length() + 4;
    }
    data = std::string(keywords_len, 'A');
}

Document::Document(const std::string& data_raw, const std::string& query_keyword, int document_size) {
    std::istringstream iss(data_raw);
    std::string line;

    std::getline(iss, line);
    std::istringstream keyword_stream(line);
    std::string keyword;
    while (std::getline(keyword_stream, keyword, ',')) {
        keywords.push_back(keyword);
    }

    std::getline(iss, line);
    real = (line == "1");

    if (real) {
        data.clear();
        while (std::getline(iss, line)) {
            data += line;
        }
    } else {
        data = std::string(document_size, 'A');
    }

    this->query_keyword = query_keyword;
}

std::vector<std::string> Document::get_keywords() const {
    return keywords;
}

void Document::set_keyword_counter(int index, int counter) {
    keywords[index] += "|" + std::to_string(counter);
}

bool Document::check_size(int document_size) const {
    int total_len = 0;
    for (const auto& keyword : keywords) {
        total_len += keyword.length() + 4;
    }
    total_len += data.length();
    return total_len > document_size;
}

int Document::get_size() const {
    int total_len = 0;
    for (const auto& keyword : keywords) {
        total_len += keyword.length() + 4;
    }
    total_len += data.length();
    return total_len;
}

std::string Document::get_data() const {
    return data;
}

void Document::set_data(const std::string& data) {
    this->data = data;
}

bool Document::isReal() const {
    return real;
}

void Document::setReal(bool real) {
    this->real = real;
}

std::vector<Document> Document::split(int document_size) const {
    std::vector<Document> documents_new;
    
    int keywords_size = 0;
    if (keywords.empty()) {
        keywords_size = 4;  
    } else {
        for (const auto& keyword : keywords) {
            keywords_size += keyword.length() + 4;
        }
    }

    double temp1 = 16.0 * keywords_size;
    double temp2 = temp1 / static_cast<double>(document_size);
    double temp3 = std::ceil(temp2);
    if (temp3 <= 0) {
        std::cerr << "Error: document_size became non-positive!" << std::endl;
        return documents_new; 
    }
    double temp4 = temp3 * document_size;
    
    document_size = static_cast<int>(temp4);
    
    document_size -= keywords_size;
    
    int original_length = static_cast<int>(data.length());
    int ii = 0;
    while (ii * document_size < original_length) 
    {
        int start_pos = ii * document_size;
        int end_pos = std::min((ii + 1) * document_size, original_length);
        
        
        Document document_new(
            keywords,
            real,
            data.substr(start_pos, end_pos - start_pos)
        );
        
        documents_new.push_back(document_new);
        ii = ii+1;
        
    }
    
    return documents_new;
}

std::string Document::get_string(int document_size) const {
    std::string result = "";
    for (const auto& keyword : keywords) {
        result += keyword + ",";
    }
    if (!result.empty()) {
        result.pop_back(); 
    }
    result += "\n";
    result += real ? "1\n" : "0\n";
    result += data + "\n";

    document_size = static_cast<int>(std::ceil(result.length() / static_cast<double>(document_size)) * document_size);
    int pad_length = document_size - result.length();
    result += std::string(pad_length, 'A');
    return result;
}

void Document::set_query_keyword(const std::string& query_keyword) {
    this->query_keyword = query_keyword;
}

bool Document::is_query_keyword(const std::string& keyword) const {
    return query_keyword == keyword;
}

bool Document::contains_keyword(const std::string& keyword) const {
    for (const auto& keyword_with_counter : keywords) {
        if (keyword_with_counter.substr(0, keyword_with_counter.find('|')) == keyword) {
            return true;
        }
    }
    return false;
}

void Document::add_keyword(const std::string& keyword) {
    keywords.push_back(keyword);
}

void Document::print() const {
    for (const auto& keyword : keywords) {
        std::cout << keyword << " ";
    }
    std::cout << std::endl;
}

void Document::clean_keywords() {
    for (auto& keyword : keywords) {
        keyword = keyword.substr(0, keyword.find('|'));
    }
}

void Document::add_keyword_counter(std::unordered_map<std::string, int>& keyword_max,
                                   std::unordered_map<std::string, int>& keyword_insert_counter) {
    for (auto& keyword : keywords) {
        keyword_insert_counter[keyword]++;
        int counter = keyword_max[keyword] + keyword_insert_counter[keyword];
        keyword += "|" + std::to_string(counter);
    }
}
