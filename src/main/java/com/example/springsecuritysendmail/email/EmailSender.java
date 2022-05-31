package com.example.springsecuritysendmail.email;

public interface EmailSender {

    void send(String to, String email);
}
