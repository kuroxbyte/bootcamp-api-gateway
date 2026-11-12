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
import org.springframework.security.web.server.SecurityWebFilterChain;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Seguridad del gateway: valida los JWT de auth-service en cada petición.
 *
 * <ul>
 *   <li>Públicas: alta de clientes ({@code POST /api/v1/customers}), registro e inicio de sesión
 *       ({@code /api/v1/auth/**}), la respuesta de respaldo del circuit breaker y el estado del
 *       gateway.
 *   <li>El resto exige {@code Authorization: Bearer <token>} con firma RS256 válida, emisor
 *       {@code jwt.issuer} y sin vencer; si no, responde 401.
 * </ul>
 *
 * <p>La clave pública llega en Base64 (DER) desde config-repo o la variable
 * {@code JWT_PUBLIC_KEY}; el gateway no consulta a auth-service.
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    /**
     * Reglas de acceso por ruta.
     */
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http,
            ProblemAuthenticationEntryPoint entryPoint) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.POST, "/api/v1/customers").permitAll()
                        .pathMatchers("/api/v1/auth/**", "/fallback", "/actuator/health")
                        .permitAll()
                        .anyExchange().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .authenticationEntryPoint(entryPoint)
                        .jwt(jwt -> { }))
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(entryPoint))
                .build();
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
