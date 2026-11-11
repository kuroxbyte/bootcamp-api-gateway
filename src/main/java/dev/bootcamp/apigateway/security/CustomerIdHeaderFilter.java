package dev.bootcamp.apigateway.security;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Envía a los microservicios el header {@code X-Customer-Id} tomado del token.
 *
 * <p>Siempre elimina el {@code X-Customer-Id} que manda el cliente; si la petición tiene un token
 * válido, lo reemplaza por su claim {@code sub} (id del cliente). Así un cliente no puede operar
 * con los productos de otro.
 */
@Component
public class CustomerIdHeaderFilter implements GlobalFilter, Ordered {

    static final String CUSTOMER_ID_HEADER = "X-Customer-Id";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerWebExchange withoutHeader = withCustomerId(exchange, null);
        return exchange.getPrincipal()
                .filter(JwtAuthenticationToken.class::isInstance)
                .map(principal -> ((JwtAuthenticationToken) principal).getToken().getSubject())
                .map(customerId -> withCustomerId(exchange, customerId))
                .defaultIfEmpty(withoutHeader)
                .flatMap(chain::filter);
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    private static ServerWebExchange withCustomerId(ServerWebExchange exchange, String customerId) {
        ServerHttpRequest request = exchange.getRequest().mutate()
                .headers(headers -> {
                    headers.remove(CUSTOMER_ID_HEADER);
                    if (customerId != null) {
                        headers.set(CUSTOMER_ID_HEADER, customerId);
                    }
                })
                .build();
        return exchange.mutate().request(request).build();
    }
}
