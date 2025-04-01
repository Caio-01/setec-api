package com.example.setec_api.infra.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.setec_api.domain.user.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {
    @Value("${api.security.token.secret}")
    private String secret;

    public String generateToken(User user) {
        try {
            // Algoritimo para armazenar a chave secreta
            Algorithm algorithm = Algorithm.HMAC256(secret);

            // Configurando para gerar o token
            String token = JWT.create()
                    .withIssuer("setec-api")
                    .withSubject(user.getEmail())
                    .withExpiresAt(this.generateExpirationDate())
                    .sign(algorithm);
            return token;

        } catch (JWTCreationException exception) {
            throw new RuntimeException("Error enquanto estava autenticando");
        }
    }

    // Metodo de validação do Token
    public String validateToken(String token){


        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.require(algorithm)
                    .withIssuer("setec-api")
                    .build()
                    .verify(token)
                    .getSubject();
            // Caso der erro na validação do Token o JWT vai abrir uma execao
        } catch (JWTVerificationException exception) {
            // Caso der erro de verificação do token
            return null;
        }
    }

    // Metodo responsavel da expiração do Token
    private Instant generateExpirationDate(){
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}
