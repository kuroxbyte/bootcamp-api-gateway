package dev.bootcamp.apigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Punto de entrada único (API Gateway) a los microservicios del banco.
 */
@SpringBootApplication
public class ApiGatewayApplication {

    /**
     * Arranca el gateway.
     *
     * @param args argumentos de la línea de comandos
     */
    public static void main(String[] args) {
        SpringApplication.run(ApiGatewayApplication.class, args);
    }
}
