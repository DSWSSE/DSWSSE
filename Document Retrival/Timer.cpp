#include "Timer.h"

Timer::Timer() {}

void Timer::start() {
    startTime.push_back(std::chrono::high_resolution_clock::now());
}


void Timer::stop() {
    endTime.push_back(std::chrono::high_resolution_clock::now());
}


long Timer::get_time(int idx) const {
    if (idx >= 0 && idx < startTime.size() && idx < endTime.size()) {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(endTime[idx] - startTime[idx]).count();
    }
    return -1; 
}

long Timer::get_total_time() const {
    long total_time = 0;
    for (size_t idx = 0; idx < startTime.size() && idx < endTime.size(); ++idx) {
        total_time += std::chrono::duration_cast<std::chrono::nanoseconds>(endTime[idx] - startTime[idx]).count();
    }
    return total_time;
}

