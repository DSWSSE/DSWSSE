#include "Index.h"
#include <string>

// Constructor initializes time_stamp and array_location
Index::Index(int time_stamp, int array_location)
    : time_stamp(time_stamp), array_location(array_location) {}

// Converts time_stamp to a string and returns it
std::string Index::get_time_stamp() const {
    return std::to_string(time_stamp);
}

// Converts array_location to a string and returns it
std::string Index::get_location() const {
    return std::to_string(array_location);
}

