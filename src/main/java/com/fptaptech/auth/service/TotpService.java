package com.fptaptech.auth.service;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Locale;

@Service
public class TotpService {

    private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final int TIME_STEP_SECONDS = 30;
    private static final int CODE_DIGITS = 6;
    private static final int DIGITS_POWER = 1_000_000;

    private final SecureRandom secureRandom = new SecureRandom();

    public String generateBase32Secret() {
        byte[] buffer = new byte[20];
        secureRandom.nextBytes(buffer);
        return encodeBase32(buffer);
    }

    public String generateCurrentCode(String base32Secret) {
        long currentInterval = Instant.now().getEpochSecond() / TIME_STEP_SECONDS;
        return generateCodeForInterval(base32Secret, currentInterval);
    }

    public boolean verifyCode(String base32Secret, String code) {
        if (base32Secret == null || code == null) return false;
        String cleanCode = code.trim().replaceAll("\\s+", "");
        if (cleanCode.length() != CODE_DIGITS) return false;

        long currentInterval = Instant.now().getEpochSecond() / TIME_STEP_SECONDS;
        // Allow -1, 0, +1 time window for clock skew
        for (int i = -1; i <= 1; i++) {
            String candidate = generateCodeForInterval(base32Secret, currentInterval + i);
            if (candidate.equals(cleanCode)) {
                return true;
            }
        }
        return false;
    }

    public String getOtpAuthUrl(String issuer, String username, String base32Secret) {
        return String.format(Locale.ROOT, "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
                issuer, username, base32Secret, issuer);
    }

    private String generateCodeForInterval(String base32Secret, long interval) {
        try {
            byte[] key = decodeBase32(base32Secret);
            byte[] data = ByteBuffer.allocate(8).putLong(interval).array();

            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0xf;
            int binary = ((hash[offset] & 0x7f) << 24)
                    | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8)
                    | (hash[offset + 3] & 0xff);

            int otp = binary % DIGITS_POWER;
            return String.format(Locale.ROOT, "%06d", otp);
        } catch (Exception e) {
            throw new IllegalStateException("Error generating TOTP code", e);
        }
    }

    private static String encodeBase32(byte[] data) {
        StringBuilder result = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xff);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                int index = (buffer >> (bitsLeft - 5)) & 0x1f;
                bitsLeft -= 5;
                result.append(BASE32_CHARS.charAt(index));
            }
        }
        if (bitsLeft > 0) {
            int index = (buffer << (5 - bitsLeft)) & 0x1f;
            result.append(BASE32_CHARS.charAt(index));
        }
        return result.toString();
    }

    private static byte[] decodeBase32(String base32) {
        String clean = base32.toUpperCase(Locale.ROOT).replaceAll("[= ]", "");
        ByteBuffer bytes = ByteBuffer.allocate(clean.length() * 5 / 8);
        int buffer = 0;
        int bitsLeft = 0;
        for (int i = 0; i < clean.length(); i++) {
            char c = clean.charAt(i);
            int val = BASE32_CHARS.indexOf(c);
            if (val < 0) {
                throw new IllegalArgumentException("Invalid Base32 character: " + c);
            }
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bytes.put((byte) ((buffer >> (bitsLeft - 8)) & 0xff));
                bitsLeft -= 8;
            }
        }
        bytes.flip();
        byte[] result = new byte[bytes.remaining()];
        bytes.get(result);
        return result;
    }
}
