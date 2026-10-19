package com.fptaptech.auth.service;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimitService {

    private static final int MAX_REGISTRATIONS_PER_HOUR = 10;
    private static final int MAX_FORGOT_PASSWORDS_PER_HOUR = 20;
    private static final long ONE_HOUR_SECONDS = 3600;

    private final Map<String, LinkedList<Instant>> registrationAttempts = new ConcurrentHashMap<>();
    private final Map<String, LinkedList<Instant>> forgotPasswordAttempts = new ConcurrentHashMap<>();

    public synchronized void resetAll() {
        registrationAttempts.clear();
        forgotPasswordAttempts.clear();
    }

    public synchronized boolean allowRegistration(String ip) {
        return checkAndRecord(ip, registrationAttempts, MAX_REGISTRATIONS_PER_HOUR);
    }

    public synchronized boolean allowForgotPassword(String ip) {
        return checkAndRecord(ip, forgotPasswordAttempts, MAX_FORGOT_PASSWORDS_PER_HOUR);
    }

    private boolean checkAndRecord(String ip, Map<String, LinkedList<Instant>> map, int maxLimit) {
        String key = (ip == null || ip.isBlank()) ? "127.0.0.1" : ip;
        Instant now = Instant.now();
        Instant threshold = now.minusSeconds(ONE_HOUR_SECONDS);

        LinkedList<Instant> timestamps = map.computeIfAbsent(key, k -> new LinkedList<>());
        
        Iterator<Instant> it = timestamps.iterator();
        while (it.hasNext()) {
            if (it.next().isBefore(threshold)) {
                it.remove();
            } else {
                break;
            }
        }

        if (timestamps.size() >= maxLimit) {
            return false;
        }

        timestamps.add(now);
        return true;
    }
}
