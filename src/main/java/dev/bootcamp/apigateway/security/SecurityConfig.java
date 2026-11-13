package dev.bootcamp.apigateway.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Seguridad del gateway: valida los JWT de auth-service en cada petición y autoriza por el rol del
 * claim {@code roles}.
 *
 * <ul>
 *   <li>Públicas: alta de clientes ({@code POST /api/v1/customers}), registro e inicio de sesión
 *       ({@code /api/v1/auth/**}), alta de monederos ({@code POST /api/v1/yanki/wallets}), la
 *       respuesta de respaldo del circuit breaker y el estado del gateway.
 *   <li>{@code /api/v1/yanki/**}: rol {@code WALLET}, salvo que un cliente autorice su tarjeta
 *       para un monedero ({@code POST /api/v1/yanki/debit-card-links}), que exige {@code CUSTOMER}.
 *   <li>El resto (productos bancarios): rol {@code CUSTOMER}.
 *   <li>Sin token, o con firma, emisor o vencimiento inválidos: 401. Con un rol que no permite la
 *       ruta: 403.
 * </ul>
 *
 * <p>La clave pública llega en Base64 (DER) desde config-repo o la variable
 * {@code JWT_PUBLIC_KEY}; el gateway no consulta a auth-service.
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    static final String ROLES_CLAIM = "roles";
    static final String CUSTOMER = "CUSTOMER";
    static final String WALLET = "WALLET";

    /**
     * Reglas de acceso por ruta.
     */
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http,
            ProblemAuthenticationEntryPoint entryPoint,
            ProblemAccessDeniedHandler accessDeniedHandler) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.POST, "/api/v1/customers").permitAll()
                        .pathMatchers("/api/v1/auth/**", "/fallback", "/actuator/health")
                        .permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/v1/yanki/wallets").permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/v1/yanki/debit-card-links")
                        .hasRole(CUSTOMER)
                        .pathMatchers("/api/v1/yanki/**").hasRole(WALLET)
                        .anyExchange().hasRole(CUSTOMER))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(rolesConverter())))
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .build();
    }

    // Cada rol del claim "roles" pasa a ser la autoridad ROLE_<rol>.
    private static ReactiveJwtAuthenticationConverterAdapter rolesConverter() {
        JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
        authorities.setAuthoritiesClaimName(ROLES_CLAIM);
        authorities.setAuthorityPrefix("ROLE_");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authorities);
        return new ReactiveJwtAuthenticationConverterAdapter(converter);
    }

    /**
     * Decodificador que valida firma RS256, vencimiento y emisor.
     */
    @Bean
    public ReactiveJwtDecoder jwtDecoder(
            @Value("${jwt.public-key}") String publicKey,
            @Value("${jwt.issuer}") String issuer) throws GeneralSecurityException {
        RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey)));
        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withPublicKey(key).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
        return decoder;
    }
}
