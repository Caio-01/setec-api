package com.example.setec_api.infra.cors;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**") // Todas as rotas estão sujeitas ao configCors
                .allowedOrigins("http://localhost:4200") // Rota do Frontend
                .allowedMethods("GET", "POST", "DELETE", "PUT"); //Metodos HTTP permitidos
    }
}