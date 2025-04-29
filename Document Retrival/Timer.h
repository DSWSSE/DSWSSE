#ifndef TIMER_H
#define TIMER_H

#include <vector>
#include <chrono>

class Timer {
private:
    std::vector<std::chrono::high_resolution_clock::time_point> startTime;
    std::vector<std::chrono::high_resolution_clock::time_point> endTime;

public:
    Timer();
    void start();
    void stop();
    long get_time(int idx) const;
    long get_total_time() const;
};

#endif // TIMER_H

