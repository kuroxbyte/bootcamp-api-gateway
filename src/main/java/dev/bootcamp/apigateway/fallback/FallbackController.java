package dev.bootcamp.apigateway.fallback;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Respuesta del gateway cuando el circuit breaker de una ruta corta la llamada: el servicio no
 * respondió en 2 segundos, falló o su circuito está abierto.
 */
@Slf4j
@RestController
public class FallbackController {

    /**
     * Responde 503 en formato Problem Details.
     *
     * @param exchange petición original redirigida por el circuit breaker
     * @return respuesta 503
     */
    @RequestMapping("/fallback")
    public Mono<ResponseEntity<ProblemDetail>> fallback(ServerWebExchange exchange) {
        log.warn("Circuit breaker fallback for {}", exchange.getRequest().getPath());
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.SERVICE_UNAVAILABLE,
                "El servicio no está disponible; intenta nuevamente en unos segundos");
        problem.setTitle("Servicio no disponible");
        return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problem));
    }
}
