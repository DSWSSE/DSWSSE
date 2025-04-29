#ifndef DOCUMENT_H
#define DOCUMENT_H
#include <vector>
#include <string>
#include <unordered_map>

class Document {
private:
    std::vector<std::string> keywords;
    bool real;
    std::string data;
    std::string query_keyword;

public:
    Document();
    
    Document(const std::vector<std::string>& keywords, bool real, const std::string& data);
    Document(const std::vector<std::string>& keywords);
    Document(const std::string& data_raw, const std::string& query_keyword, int document_size);
    
    std::vector<std::string> get_keywords() const;
    void set_keyword_counter(int index, int counter);
    bool check_size(int document_size) const;
    int get_size() const;
    std::string get_data() const;
    void set_data(const std::string& data);
    bool isReal() const;
    void setReal(bool real);
    std::vector<Document> split(int document_size) const;
    std::string get_string(int document_size) const;
    void set_query_keyword(const std::string& query_keyword);
    bool is_query_keyword(const std::string& keyword) const;
    bool contains_keyword(const std::string& keyword) const;
    void add_keyword(const std::string& keyword);
    void print() const;
    void clean_keywords();
    void add_keyword_counter(std::unordered_map<std::string, int>& keyword_max,
                             std::unordered_map<std::string, int>& keyword_insert_counter);
};
#endif // DOCUMENT_H