package com.javainuse.springsecurity.config;

import com.javainuse.springsecurity.model.DAOUser;
import com.javainuse.springsecurity.model.UserDTO;
import com.javainuse.springsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

import static com.javainuse.springsecurity.config.HttpBasicSecurityConfig.bCryptPasswordEncoder;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("CustomUserDetailsService.loadUserByUsername");
        List<SimpleGrantedAuthority> roles = null;

        DAOUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with the name " + username));

        System.out.println("user.getUsername() = " + user.getUsername());
        roles = List.of(new SimpleGrantedAuthority(user.getRole()));
        return new User(user.getUsername(), user.getPassword(), roles);
    }

    public DAOUser save(UserDTO userDTO) {
        DAOUser newUser = new DAOUser();
        newUser.setUsername(userDTO.getUsername());
        newUser.setPassword(bCryptPasswordEncoder().encode(userDTO.getPassword()));
        newUser.setRole(userDTO.getRole());
        return userRepository.save(newUser);
    }
}
