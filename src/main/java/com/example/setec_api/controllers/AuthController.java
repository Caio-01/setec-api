package com.example.setec_api.controllers;

import com.example.setec_api.domain.user.User;
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
        User user = this.respository.findByEmail(body.email()).orElseThrow(() -> new RuntimeException("User nao encontrado"));
        if(passwordEncoder.matches(body.password(), user.getPassword())){
            String token = this.tokenService.generateToken(user);

            return ResponseEntity.ok(new ResponseDTO(user.getName(), token));
        }
        // Se as senhas não der matches
        return ResponseEntity.badRequest().build();
    }

    // Requisição de Register
    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterRequestDTO body){
        Optional<User> user = this.respository.findByEmail(body.email());
        // Se o usuario nao estiver criado
        if(user.isEmpty()){
            User newUser = new User();
            newUser.setPassword(passwordEncoder.encode(body.password()));
            newUser.setEmail(body.email());
            newUser.setName(body.name());
            // Salva no repository
            this.respository.save(newUser);

            // Gera o token
            String token = this.tokenService.generateToken(newUser);
            return ResponseEntity.ok(new ResponseDTO(newUser.getName(), token));

        }
        return ResponseEntity.badRequest().build();
    }
}
