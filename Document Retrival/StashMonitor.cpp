#include "StashMonitor.h"
#include <stdexcept>

// Adds a size to the stash_sizes vector
void StashMonitor::add(int size) {
    stash_sizes.push_back(size);
}

// Retrieves a size from stash_sizes at the specified index
int StashMonitor::get(int idx) const {
    if (idx >= 0 && idx < stash_sizes.size()) {
        return stash_sizes[idx];
    }
    throw std::out_of_range("Index out of range");
    return stash_sizes[idx];
}

