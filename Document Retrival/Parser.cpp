#include "Parser.h"
#include <fstream>
#include <sstream>
#include <filesystem>

namespace fs = std::filesystem;

void Parser::parse_documents(std::vector<Document>& documents, const std::unordered_map<std::string, std::string>& configuration) {
    int documents_max = std::stoi(configuration.at("N_emails"));
    if (documents_max < 0) {
        documents_max = std::numeric_limits<int>::max();
    }
    int document_count = 0;

    // Get the folder path from configuration
    fs::path folder_path(configuration.at("folder_emails"));

    for (const auto& entry : fs::directory_iterator(folder_path)) {
        if (!entry.is_regular_file()) {
            continue;
        }

        // Open the file
        std::ifstream file(entry.path());
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open file: " + entry.path().string());
        }

        std::string line;
        
        // Read keywords from the first line
        if (!std::getline(file, line)) {
            continue;
        }
        std::istringstream keyword_stream(line);
        std::vector<std::string> keywords;
        std::string keyword;
        while (std::getline(keyword_stream, keyword, ',')) {
            keywords.push_back(keyword);
        }

        // Read the rest of the file as main_body
        std::string main_body;
        while (std::getline(file, line)) {
            main_body += line + "\n";
        }

        // Create a Document and add it to the list
        Document document(keywords, true, main_body);
        documents.push_back(document);

        file.close();
        document_count++;

        if (document_count >= documents_max) {
            break;
        }
    }
}

