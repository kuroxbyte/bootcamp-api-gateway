package dev.bootcamp.apigateway;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.cloud.client.circuitbreaker.ReactiveCircuitBreakerFactory;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * Circuit breaker del gateway: filtro en cada ruta, timeout de 2 s y respuesta de respaldo 503.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CircuitBreakerTest {

    @LocalServerPort
    private int port;

    @Autowired
    private RouteLocator routeLocator;

    @Autowired
    private ReactiveCircuitBreakerFactory<?, ?> circuitBreakerFactory;

    @Test
    void everyRouteHasCircuitBreakerFilter() {
        assertThat(Flux.from(routeLocator.getRoutes()).collectList().block())
                .isNotEmpty()
                .allSatisfy(route -> assertThat(route.getFilters())
                        .anySatisfy(filter -> assertThat(filter.toString())
                                .contains("CircuitBreaker")));
    }

    @Test
    void callsTimeOutAfterTwoSeconds() {
        long start = System.nanoTime();

        String result = circuitBreakerFactory.create("config-check")
                .run(Mono.<String>never(), error -> Mono.just("timeout"))
                .block(Duration.ofSeconds(5));

        Duration elapsed = Duration.ofNanos(System.nanoTime() - start);
        assertThat(result).isEqualTo("timeout");
        assertThat(elapsed).isBetween(Duration.ofMillis(1900), Duration.ofMillis(3000));
    }

    @Test
    void fallbackRespondsServiceUnavailableAsProblemDetails() {
        HttpServerErrorException error = catchThrowableOfType(
                HttpServerErrorException.class,
                () -> RestClient.create("http://localhost:" + port)
                        .get()
                        .uri("/fallback")
                        .retrieve()
                        .body(String.class));

        assertThat(error.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(error.getResponseBodyAsString()).contains("Servicio no disponible");
    }
}
