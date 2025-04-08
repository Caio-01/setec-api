package com.example.setec_api.infra.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomUserDetailsService userDetailsService; // Injetando o servico que busca os usuarios no banco

    @Autowired
    SecurityFilter securityFilter; // Injetando o filtro de sergurança personalizado para validar o token

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // Desativa a proteção CSRF
                .cors(withDefaults()) // Instrui o Security a usar as config do CORS
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Define que a API não mantem sessoes de autenticação, pois usa o JWT
                // Define as permissoes de acesso para diferentes endpoint da API
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()// Liberado sem autenticação
                        .requestMatchers(HttpMethod.POST, "/auth/register").permitAll() // Liberado sem autenticação
                        .anyRequest().authenticated() // Qualquer outra req precisa esta autenticado
                )
                // Adiciona um filtro personalizado antes do filtro padrão do Spring Security
                .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build(); // retorna a config pronta
    }

    // Metodo que define o algoritmo de criptografia para a senha
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // Algoritmo usado para criptografar
    }

    // Metodo que configura o gerenciador de autenticação
    // Bean indica que esse metodo cria um objeto gerenciado pelo Spring, ou seja, permite q seja injetado em outras partes do codigo
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        // Obtém e retorna o AuthenticationManager configurado pelo Spring Security
        return authenticationConfiguration.getAuthenticationManager();
    }
}
