#ifndef KEYWORDSCOMPARATOR_H
#define KEYWORDSCOMPARATOR_H

#include <string>
#include <unordered_map>

class KeywordsComparator {
private:
    std::unordered_map<std::string, int> keyword_count;

public:
    KeywordsComparator(const std::unordered_map<std::string, int>& keyword_count);
    bool compare(const std::string& o1, const std::string& o2) const;
};

#endif // KEYWORDSCOMPARATOR_H

