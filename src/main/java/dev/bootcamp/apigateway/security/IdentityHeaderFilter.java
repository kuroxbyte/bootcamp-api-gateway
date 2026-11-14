package dev.bootcamp.apigateway.security;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Envía a los microservicios la identidad tomada del token, con el claim {@code sub}:
 * {@code X-Customer-Id} para un token de cliente, {@code X-Wallet-Id} para uno de monedero Yanki
 * (rol {@code WALLET}) y {@code X-Admin-Id} para uno de empleado (rol {@code ADMIN}).
 *
 * <p>Siempre elimina los tres headers que manda el cliente antes de poner el que corresponde. Así
 * nadie puede operar con los productos o el monedero de otro, ni hacerse pasar por empleado.
 */
@Component
public class IdentityHeaderFilter implements GlobalFilter, Ordered {

    static final String CUSTOMER_ID_HEADER = "X-Customer-Id";
    static final String WALLET_ID_HEADER = "X-Wallet-Id";
    static final String ADMIN_ID_HEADER = "X-Admin-Id";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerWebExchange withoutIdentity = withIdentity(exchange, null, null);
        return exchange.getPrincipal()
                .filter(JwtAuthenticationToken.class::isInstance)
                .map(principal -> ((JwtAuthenticationToken) principal).getToken())
                .map(jwt -> withIdentity(exchange, headerFor(jwt), jwt.getSubject()))
                .defaultIfEmpty(withoutIdentity)
                .flatMap(chain::filter);
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    private static String headerFor(Jwt jwt) {
        List<String> roles = jwt.getClaimAsStringList(SecurityConfig.ROLES_CLAIM);
        if (roles == null) {
            return CUSTOMER_ID_HEADER;
        }
        if (roles.contains(SecurityConfig.ADMIN)) {
            return ADMIN_ID_HEADER;
        }
        return roles.contains(SecurityConfig.WALLET) ? WALLET_ID_HEADER : CUSTOMER_ID_HEADER;
    }

    private static ServerWebExchange withIdentity(
            ServerWebExchange exchange,
            String header,
            String id) {
        ServerHttpRequest request = exchange.getRequest().mutate()
                .headers(headers -> {
                    headers.remove(CUSTOMER_ID_HEADER);
                    headers.remove(WALLET_ID_HEADER);
                    headers.remove(ADMIN_ID_HEADER);
                    if (header != null) {
                        headers.set(header, id);
                    }
                })
                .build();
        return exchange.mutate().request(request).build();
    }
}
