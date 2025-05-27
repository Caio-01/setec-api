package com.example.setec_api.infra.security;

import com.example.setec_api.entities.User;
import com.example.setec_api.repositories.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
public class SecurityFilter extends OncePerRequestFilter {
    //OncePerRequestFilter vai garantir que o filtro será executado apenas uma vez por req

    @Autowired
    TokenService tokenService;
    @Autowired
    UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var token = this.recoverToken(request); // Chama o metodo recoverToken para obter o TOKEN JWT do Cabeçalho, se não existir o valor será null
        var login = tokenService.validateToken(token); // Metodo que verifica se o token é valido e retorna o nome do usuario ou null se for invalido

        if(login != null){
            // Se token for valido, vai buscar o usuario no banco, mas se nao encontrar orElseThrow lança a exceção
            User user = userRepository.findByEmail(login).orElseThrow(() -> new RuntimeException("User nao encontrado"));
            var authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")); // Collections.singletonList Cria uma lista com apenas um valor: autoridade (ROLE_USER) E SimpleGrantedAuthority representa a permissão/autorizaçao concedida peli user
            var authentication = new UsernamePasswordAuthenticationToken(user, null, authorities); // UsernamePassword.. cria um obj de autenticaçao com usuario e suas permissoes
            SecurityContextHolder.getContext().setAuthentication(authentication); // Configura o contexto de segurança do Sping com o obj de autenticaçao
        }
        filterChain.doFilter(request, response);
    }

    // Metodo para recuperar o token
    private String recoverToken(HttpServletRequest request){
        var authHeader = request.getHeader("Authorization"); // Pega o valor do cabeçalho Authorization da req HTTP
        if(authHeader == null) return null; // Se não existir o cabeçalho, vai retornar null
        return authHeader.replace("Bearer ", ""); // Remove o prefixo Bearer e os espaços em branco, apenas vai ter o token
    }
}
