#ifndef PARSER_H
#define PARSER_H

#include <vector>
#include <unordered_map>
#include <string>
#include "Document.h"

class Parser {
public:
    static void parse_documents(std::vector<Document>& documents, const std::unordered_map<std::string, std::string>& configuration);
};

#endif // PARSER_H

