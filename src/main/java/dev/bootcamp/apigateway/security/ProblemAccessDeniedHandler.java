package dev.bootcamp.apigateway.security;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * Responde 403 en formato Problem Details cuando el token es válido pero su rol no permite la
 * ruta (por ejemplo, un token de monedero en una ruta de productos bancarios).
 */
@Component
public class ProblemAccessDeniedHandler implements ServerAccessDeniedHandler {

    private static final String BODY = "{\"title\":\"Acceso denegado\",\"status\":403,"
            + "\"detail\":\"El token no permite usar esta ruta\"}";

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {
        var response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN);
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        return response.writeWith(Mono.just(
                response.bufferFactory().wrap(BODY.getBytes(StandardCharsets.UTF_8))));
    }
}
