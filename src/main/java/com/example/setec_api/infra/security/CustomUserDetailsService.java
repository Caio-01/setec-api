package com.example.setec_api.infra.security;

import com.example.setec_api.domain.user.User;
import com.example.setec_api.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Component
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository repository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Busca o usuário no banco pelo nome, se não encontrar lança uma exceção
        User user = this.repository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException("User nao encontrado"));
        // Retorna um obj UserDetails do Spring com nome, password e lista de permissão
        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword(),
                new ArrayList<>()
        );

    }
}
