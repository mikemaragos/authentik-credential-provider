// RateLimiter.h
// Brute force protection and rate limiting for authentication attempts

#pragma once

#include <windows.h>
#include <string>
#include <map>
#include <queue>
#include <chrono>
#include <mutex>

/// <summary>
/// Rate limiter to prevent brute force attacks
/// Tracks failed authentication attempts per user and enforces lockout periods
/// </summary>
class RateLimiter {
public:
    /// <summary>
    /// Constructor with default settings
    /// </summary>
    RateLimiter();

    /// <summary>
    /// Constructor with custom settings
    /// </summary>
    /// <param name="maxAttempts">Maximum failed attempts before lockout</param>
    /// <param name="windowSeconds">Time window for counting attempts (seconds)</param>
    /// <param name="lockoutMinutes">Lockout duration after max attempts (minutes)</param>
    RateLimiter(int maxAttempts, int windowSeconds, int lockoutMinutes);

    /// <summary>
    /// Check if an authentication attempt is allowed for this user
    /// </summary>
    /// <param name="username">Username to check</param>
    /// <returns>True if attempt is allowed, false if rate limited or locked out</returns>
    bool AllowAttempt(const std::wstring& username);

    /// <summary>
    /// Record a failed authentication attempt
    /// </summary>
    /// <param name="username">Username that failed</param>
    void RecordFailure(const std::wstring& username);

    /// <summary>
    /// Record a successful authentication (clears failure history)
    /// </summary>
    /// <param name="username">Username that succeeded</param>
    void RecordSuccess(const std::wstring& username);

    /// <summary>
    /// Check if user is currently locked out
    /// </summary>
    /// <param name="username">Username to check</param>
    /// <returns>True if user is locked out</returns>
    bool IsLockedOut(const std::wstring& username);

    /// <summary>
    /// Get remaining lockout time for a user
    /// </summary>
    /// <param name="username">Username to check</param>
    /// <returns>Remaining lockout time in seconds (0 if not locked out)</returns>
    int GetRemainingLockoutSeconds(const std::wstring& username);

    /// <summary>
    /// Manually clear history for a user (admin action)
    /// </summary>
    /// <param name="username">Username to clear</param>
    void ClearHistory(const std::wstring& username);

    /// <summary>
    /// Get current failed attempt count for user
    /// </summary>
    /// <param name="username">Username to check</param>
    /// <returns>Number of failed attempts in current window</returns>
    int GetFailedAttemptCount(const std::wstring& username);

private:
    /// <summary>
    /// Attempt history for a single user
    /// </summary>
    struct AttemptHistory {
        std::queue<std::chrono::steady_clock::time_point> attempts;
        std::chrono::steady_clock::time_point lockoutUntil;
        int totalFailures;
        
        AttemptHistory() : totalFailures(0) {}
    };

    std::map<std::wstring, AttemptHistory> _history;
    std::mutex _historyMutex;

    // Configuration
    int _maxAttempts;
    std::chrono::seconds _attemptWindow;
    std::chrono::minutes _lockoutDuration;

    /// <summary>
    /// Clean up old attempts outside the window
    /// </summary>
    void CleanupOldAttempts(AttemptHistory& history);
};

// Implementation

inline RateLimiter::RateLimiter()
    : _maxAttempts(5),
      _attemptWindow(60),  // 60 seconds
      _lockoutDuration(15) // 15 minutes
{
}

inline RateLimiter::RateLimiter(int maxAttempts, int windowSeconds, int lockoutMinutes)
    : _maxAttempts(maxAttempts),
      _attemptWindow(windowSeconds),
      _lockoutDuration(lockoutMinutes)
{
}

inline bool RateLimiter::AllowAttempt(const std::wstring& username)
{
    std::lock_guard<std::mutex> lock(_historyMutex);

    auto now = std::chrono::steady_clock::now();
    auto& history = _history[username];

    // Check if locked out
    if (history.lockoutUntil > now) {
        return false;
    }

    // Clear lockout if expired
    if (history.lockoutUntil <= now && history.lockoutUntil != std::chrono::steady_clock::time_point()) {
        history.lockoutUntil = std::chrono::steady_clock::time_point();
        history.attempts = std::queue<std::chrono::steady_clock::time_point>();
        history.totalFailures = 0;
    }

    // Clean up old attempts
    CleanupOldAttempts(history);

    // Check if within rate limit
    return history.attempts.size() < static_cast<size_t>(_maxAttempts);
}

inline void RateLimiter::RecordFailure(const std::wstring& username)
{
    std::lock_guard<std::mutex> lock(_historyMutex);

    auto now = std::chrono::steady_clock::now();
    auto& history = _history[username];

    // Clean up old attempts
    CleanupOldAttempts(history);

    // Record this attempt
    history.attempts.push(now);
    history.totalFailures++;

    // Check if should lock out
    if (history.attempts.size() >= static_cast<size_t>(_maxAttempts)) {
        history.lockoutUntil = now + _lockoutDuration;
    }
}

inline void RateLimiter::RecordSuccess(const std::wstring& username)
{
    std::lock_guard<std::mutex> lock(_historyMutex);

    // Clear history on successful auth
    _history.erase(username);
}

inline bool RateLimiter::IsLockedOut(const std::wstring& username)
{
    std::lock_guard<std::mutex> lock(_historyMutex);

    auto it = _history.find(username);
    if (it == _history.end()) {
        return false;
    }

    auto now = std::chrono::steady_clock::now();
    return it->second.lockoutUntil > now;
}

inline int RateLimiter::GetRemainingLockoutSeconds(const std::wstring& username)
{
    std::lock_guard<std::mutex> lock(_historyMutex);

    auto it = _history.find(username);
    if (it == _history.end()) {
        return 0;
    }

    auto now = std::chrono::steady_clock::now();
    if (it->second.lockoutUntil <= now) {
        return 0;
    }

    auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
        it->second.lockoutUntil - now);
    return static_cast<int>(remaining.count());
}

inline void RateLimiter::ClearHistory(const std::wstring& username)
{
    std::lock_guard<std::mutex> lock(_historyMutex);
    _history.erase(username);
}

inline int RateLimiter::GetFailedAttemptCount(const std::wstring& username)
{
    std::lock_guard<std::mutex> lock(_historyMutex);

    auto it = _history.find(username);
    if (it == _history.end()) {
        return 0;
    }

    auto& history = it->second;
    CleanupOldAttempts(history);
    
    return static_cast<int>(history.attempts.size());
}

inline void RateLimiter::CleanupOldAttempts(AttemptHistory& history)
{
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - _attemptWindow;

    while (!history.attempts.empty() && history.attempts.front() < cutoff) {
        history.attempts.pop();
    }
}
