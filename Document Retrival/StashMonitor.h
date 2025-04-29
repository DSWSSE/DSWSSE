#ifndef STASHMONITOR_H
#define STASHMONITOR_H

#include <vector>

class StashMonitor {
private:
    std::vector<int> stash_sizes;

public:
    void add(int size);
    int get(int idx) const;
};

#endif // STASHMONITOR_H

