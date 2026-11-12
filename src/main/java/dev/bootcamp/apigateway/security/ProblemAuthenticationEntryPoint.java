package dev.bootcamp.apigateway.security;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * Responde 401 en formato Problem Details cuando falta el token o no es válido, como el resto de
 * errores de la API.
 */
@Component
public class ProblemAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    private static final String BODY = "{\"title\":\"No autenticado\",\"status\":401,"
            + "\"detail\":\"Falta el token de acceso o no es válido\"}";

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        var response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        return response.writeWith(Mono.just(
                response.bufferFactory().wrap(BODY.getBytes(StandardCharsets.UTF_8))));
    }
}
