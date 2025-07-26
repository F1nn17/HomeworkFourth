package com.shiraku.homeworkfourth.utils;

import jakarta.security.auth.message.AuthException;
import jakarta.servlet.http.Cookie;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Component
public class CookieUtil {
    public static String extractCookie(Cookie[] cookies, String name) throws AuthException {
        if (cookies == null) {
            throw new AuthException("Missing cookies");
        }

        return Arrays.stream(cookies)
                .filter(c -> name.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElseThrow(() -> new AuthException("Missing refresh token cookie"));
    }

}
