package com.example.springsecuritysendmail.appuser;

import com.example.springsecuritysendmail.registration.token.ConfirmationToken;
import com.example.springsecuritysendmail.registration.token.ConfirmationTokenService;
import com.example.springsecuritysendmail.security.PasswordEncoder;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@AllArgsConstructor
public class AppUserService implements UserDetailsService {
    private final static String USER_NOT_FOUND_MSG = "user with email %s not found";
    private final AppUserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ConfirmationTokenService confirmationTokenService;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository
                .findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG, email)));
    }

    public String signUpUser(AppUser appUser) {
        String token = UUID.randomUUID().toString();

        boolean userExists = userRepository.findByEmail(appUser.getEmail())
                .isPresent();
        if (userExists) {
            AppUser userByEmail = userRepository.findByEmail(appUser.getEmail()).get();
            if (userByEmail != null
                    && userByEmail.getFirstName().equals(appUser.getFirstName())
                    && userByEmail.getLastName().equals(appUser.getLastName())) {
                confirmationTokenService.updateConfirmationToken(appUser.getId(), token);
                return token;
            } else {
                throw new IllegalStateException("email already taken");
            }
        }

        String encodedPassword = bCryptPasswordEncoder.encode(appUser.getPassword());
        appUser.setPassword(encodedPassword);
        userRepository.save(appUser);

        ConfirmationToken confirmationToken = new ConfirmationToken(
                token,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                appUser);
        confirmationTokenService.saveConfirmationToken(confirmationToken);
        return token;
    }
    public int enableAppUser(String email) {
        return userRepository.enableAppUser(email);
    }

}
