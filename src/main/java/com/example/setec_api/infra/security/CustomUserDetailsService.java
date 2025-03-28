package com.example.setec_api.infra.security;

import com.example.setec_api.domain.user.User;
import com.example.setec_api.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.ArrayList;

public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository repository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = this.repository.findByName(username).orElseThrow(() -> new UsernameNotFoundException("User nao encontrado"));
        return new org.springframework.security.core.userdetails.User(user.getName(),user.getPassword(), new ArrayList<>());
    }
}
