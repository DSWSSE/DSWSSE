#include "KeywordsComparator.h"

// Constructor initializes keyword_count with the provided map
KeywordsComparator::KeywordsComparator(const std::unordered_map<std::string, int>& keyword_count)
    : keyword_count(keyword_count) {}

// Compare function returns true if o1 should come before o2, false otherwise
bool KeywordsComparator::compare(const std::string& o1, const std::string& o2) const {
    auto it1 = keyword_count.find(o1);
    auto it2 = keyword_count.find(o2);

    int count1 = (it1 != keyword_count.end()) ? it1->second : 0;
    int count2 = (it2 != keyword_count.end()) ? it2->second : 0;

    if (count1 > count2) return true;
    if (count1 < count2) return false;
    return o1 < o2; // If counts are equal, use alphabetical order as secondary criteria
}

