package dev.bootcamp.apigateway;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifica que cada ruta de la API llegue al microservicio que la implementa.
 */
@SpringBootTest
class ApiGatewayRoutesTest {

    @Autowired
    private RouteLocator routeLocator;

    @ParameterizedTest(name = "{0} {1} -> {2}")
    @CsvSource({
        "POST, /api/v1/customers, customer-service",
        "GET, /api/v1/customers/c1, customer-service",
        "POST, /api/v1/accounts/savings, account-service",
        "GET, /api/v1/accounts, account-service",
        "GET, /api/v1/accounts/a1, account-service",
        "POST, /api/v1/accounts/a1/deposits, transaction-service",
        "POST, /api/v1/accounts/a1/withdrawals, transaction-service",
        "GET, /api/v1/accounts/a1/balance, transaction-service",
        "GET, /api/v1/accounts/a1/daily-average, transaction-service",
        "GET, /api/v1/accounts/a1/movements, transaction-service",
        "POST, /api/v1/accounts/a1/transfers/own, transaction-service",
        "POST, /api/v1/accounts/a1/transfers/third-party, transaction-service",
        "POST, /api/v1/credits, credit-service",
        "GET, /api/v1/credits/k1, credit-service",
        "POST, /api/v1/credits/k1/payments, transaction-service",
        "GET, /api/v1/credits/k1/movements, transaction-service",
        "POST, /api/v1/credit-cards, credit-service",
        "GET, /api/v1/credit-cards/t1, credit-service",
        "POST, /api/v1/credit-cards/t1/charges, transaction-service",
        "POST, /api/v1/credit-cards/t1/payments, transaction-service",
        "GET, /api/v1/credit-cards/t1/available-credit, transaction-service",
        "GET, /api/v1/credit-cards/t1/movements, transaction-service"
    })
    void routesEachPathToItsService(String method, String path, String service) {
        URI target = routeFor(HttpMethod.valueOf(method), path).getUri();

        assertThat(target).isEqualTo(URI.create("lb://" + service));
    }

    private Route routeFor(HttpMethod method, String path) {
        MockServerWebExchange exchange =
                MockServerWebExchange.from(MockServerHttpRequest.method(method, path));
        return Flux.from(routeLocator.getRoutes())
                .concatMap(route -> Mono.from(route.getPredicate().apply(exchange))
                        .filter(Boolean::booleanValue)
                        .map(matches -> route))
                .blockFirst();
    }
}
