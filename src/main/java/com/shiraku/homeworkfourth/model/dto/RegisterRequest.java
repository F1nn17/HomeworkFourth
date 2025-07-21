package com.shiraku.homeworkfourth.model.dto;


import java.util.Set;

public record RegisterRequest(
        String login,
        String password,
        String email,
        Set<String> roles
) {}
