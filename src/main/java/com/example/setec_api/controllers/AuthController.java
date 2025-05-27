package com.example.setec_api.controllers;

import com.example.setec_api.entities.User;
import com.example.setec_api.dto.LoginRequestDTO;
import com.example.setec_api.dto.RegisterRequestDTO;
import com.example.setec_api.dto.ResponseDTO;
import com.example.setec_api.infra.security.TokenService;
import com.example.setec_api.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository respository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    // Requisição de Login
    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginRequestDTO body){
        // Procura um usuário com o email fornecido
        User user = this.respository.findByEmail(body.email()).orElseThrow(() -> new RuntimeException("User nao encontrado"));
        // Verifica se a senha enviada bate com a que esta no banco cripto
        if(passwordEncoder.matches(body.password(), user.getPassword())){
            String token = this.tokenService.generateToken(user);// Gera um token JWT

            return ResponseEntity.ok(new ResponseDTO(user.getName(), token));// Retorna um obj com nome e token
        }
        // Se as senhas não der matches, retorna um erro 400
        return ResponseEntity.badRequest().build();
    }

    // Requisição de Register
    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterRequestDTO body){
        // Verifica se ja existe algum usuario criado com esse email
        Optional<User> user = this.respository.findByEmail(body.email());
        // Se não existir faz o cadastro
        if(user.isEmpty()){
            User newUser = new User();
            newUser.setPassword(passwordEncoder.encode(body.password()));
            newUser.setEmail(body.email());
            newUser.setName(body.name());
            // Salva o usuario no banco (repository)
            this.respository.save(newUser);

            // Gera o token
            String token = this.tokenService.generateToken(newUser);
            return ResponseEntity.ok(new ResponseDTO(newUser.getName(), token));

        }
        // Se o email ja estiver cadastrado, retorna um erro 400
        return ResponseEntity.badRequest().build();
    }
}
