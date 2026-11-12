package dev.bootcamp.apigateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class CustomerIdHeaderFilterTest {

    private final CustomerIdHeaderFilter filter = new CustomerIdHeaderFilter();

    private final AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();

    private final GatewayFilterChain chain = exchange -> {
        forwarded.set(exchange);
        return Mono.empty();
    };

    private static ServerWebExchange requestWithForgedHeader() {
        return MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/accounts")
                .header("X-Customer-Id", "otro-cliente"));
    }

    @Test
    void replacesForgedHeaderWithTokenSubject() {
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256").subject("c1").build();
        ServerWebExchange exchange = requestWithForgedHeader().mutate()
                .principal(Mono.just(new JwtAuthenticationToken(jwt)))
                .build();

        filter.filter(exchange, chain).block();

        assertThat(forwarded.get().getRequest().getHeaders().get("X-Customer-Id"))
                .containsExactly("c1");
    }

    @Test
    void removesHeaderWhenThereIsNoToken() {
        filter.filter(requestWithForgedHeader(), chain).block();

        assertThat(forwarded.get().getRequest().getHeaders().containsHeader("X-Customer-Id"))
                .isFalse();
    }
}
