package dev.bootcamp.apigateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class IdentityHeaderFilterTest {

    private final IdentityHeaderFilter filter = new IdentityHeaderFilter();

    private final AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();

    private final GatewayFilterChain chain = exchange -> {
        forwarded.set(exchange);
        return Mono.empty();
    };

    private static ServerWebExchange requestWithForgedHeaders() {
        return MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/accounts")
                .header("X-Customer-Id", "otro-cliente")
                .header("X-Wallet-Id", "otro-monedero"));
    }

    private HttpHeaders forwardedHeaders(Jwt jwt) {
        ServerWebExchange exchange = requestWithForgedHeaders().mutate()
                .principal(Mono.just(new JwtAuthenticationToken(jwt)))
                .build();
        filter.filter(exchange, chain).block();
        return forwarded.get().getRequest().getHeaders();
    }

    private static Jwt token(String subject, String role) {
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject(subject)
                .claim("roles", List.of(role))
                .build();
    }

    @Test
    void customerTokenSendsOnlyTheCustomerId() {
        HttpHeaders headers = forwardedHeaders(token("c1", "CUSTOMER"));

        assertThat(headers.get("X-Customer-Id")).containsExactly("c1");
        assertThat(headers.containsHeader("X-Wallet-Id")).isFalse();
    }

    @Test
    void walletTokenSendsOnlyTheWalletId() {
        HttpHeaders headers = forwardedHeaders(token("w1", "WALLET"));

        assertThat(headers.get("X-Wallet-Id")).containsExactly("w1");
        assertThat(headers.containsHeader("X-Customer-Id")).isFalse();
    }

    @Test
    void tokenWithoutRolesIsTreatedAsCustomer() {
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256").subject("c1").build();

        assertThat(forwardedHeaders(jwt).get("X-Customer-Id")).containsExactly("c1");
    }

    @Test
    void removesBothHeadersWhenThereIsNoToken() {
        filter.filter(requestWithForgedHeaders(), chain).block();

        HttpHeaders headers = forwarded.get().getRequest().getHeaders();
        assertThat(headers.containsHeader("X-Customer-Id")).isFalse();
        assertThat(headers.containsHeader("X-Wallet-Id")).isFalse();
    }
}
