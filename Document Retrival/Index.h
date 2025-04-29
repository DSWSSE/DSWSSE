#ifndef INDEX_H
#define INDEX_H

#include <string>

class Index {
private:
    int time_stamp;
    int array_location;

public:
 // Default constructor
    Index() : time_stamp(0), array_location(0) {}
    Index(int time_stamp, int array_location);

    std::string get_time_stamp() const;
    std::string get_location() const;
};

#endif // INDEX_H

