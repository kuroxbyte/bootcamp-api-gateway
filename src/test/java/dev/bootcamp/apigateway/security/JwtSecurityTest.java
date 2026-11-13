package dev.bootcamp.apigateway.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

/**
 * Seguridad del gateway: rutas públicas, 401 sin token o con un token inválido, 403 si el rol no
 * permite la ruta, y paso de las peticiones con un token válido (sin servicios registrados
 * responden 503 por el circuit breaker).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JwtSecurityTest {

    private static final KeyPair KEYS = rsaKeyPair();
    private static final KeyPair OTHER_KEYS = rsaKeyPair();
    private static final String ISSUER = "bank-auth-service";

    @LocalServerPort
    private int port;

    private WebTestClient client;

    @DynamicPropertySource
    static void jwtProperties(DynamicPropertyRegistry registry) {
        registry.add("jwt.public-key", () ->
                Base64.getEncoder().encodeToString(KEYS.getPublic().getEncoded()));
        registry.add("jwt.issuer", () -> ISSUER);
    }

    private static KeyPair rsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String token(KeyPair keys, String issuer, Instant expiresAt) {
        return token(keys, issuer, expiresAt, List.of("CUSTOMER"));
    }

    private static String token(
            KeyPair keys,
            String issuer,
            Instant expiresAt,
            List<String> roles) {
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keys.getPublic())
                .privateKey((RSAPrivateKey) keys.getPrivate())
                .build();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject("c1")
                .issuedAt(expiresAt.minusSeconds(3600))
                .expiresAt(expiresAt)
                .claim("roles", roles)
                .build();
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(rsaKey)))
                .encode(JwtEncoderParameters.from(
                        JwsHeader.with(SignatureAlgorithm.RS256).build(),
                        claims))
                .getTokenValue();
    }

    private static String validToken() {
        return token(KEYS, ISSUER, Instant.now().plusSeconds(3600));
    }

    private static String tokenWithRoles(List<String> roles) {
        return token(KEYS, ISSUER, Instant.now().plusSeconds(3600), roles);
    }

    @BeforeEach
    void createClient() {
        client = WebTestClient.bindToServer().baseUrl("http://localhost:" + port).build();
    }

    @Test
    void rejectsRequestWithoutTokenAsProblemDetails() {
        client.get().uri("/api/v1/accounts").exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, "Bearer")
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.detail").isEqualTo("Falta el token de acceso o no es válido");
    }

    @Test
    void rejectsExpiredTokenWrongIssuerAndForeignSignature() {
        String expired = token(KEYS, ISSUER, Instant.now().minusSeconds(120));
        String wrongIssuer = token(KEYS, "otro-emisor", Instant.now().plusSeconds(3600));
        String foreignSignature = token(OTHER_KEYS, ISSUER, Instant.now().plusSeconds(3600));

        for (String token : new String[] {expired, wrongIssuer, foreignSignature, "no-es-jwt"}) {
            client.get().uri("/api/v1/accounts")
                    .headers(headers -> headers.setBearerAuth(token))
                    .exchange()
                    .expectStatus().isUnauthorized();
        }
    }

    @Test
    void letsValidTokenThroughToTheRoute() {
        client.get().uri("/api/v1/accounts")
                .headers(headers -> headers.setBearerAuth(validToken()))
                .exchange()
                .expectStatus().isEqualTo(503);
    }

    @Test
    void customerCreationAndAuthEndpointsArePublic() {
        client.post().uri("/api/v1/customers")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isEqualTo(503);
        client.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isEqualTo(503);
    }

    @Test
    void readingCustomerRequiresToken() {
        client.get().uri("/api/v1/customers/c1").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void walletTokenCannotUseBankRoutes() {
        client.get().uri("/api/v1/accounts")
                .headers(headers -> headers.setBearerAuth(tokenWithRoles(List.of("WALLET"))))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.detail").isEqualTo("El token no permite usar esta ruta");
    }

    @Test
    void tokenWithoutRolesCannotUseBankRoutes() {
        client.get().uri("/api/v1/accounts")
                .headers(headers -> headers.setBearerAuth(tokenWithRoles(List.of())))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void yankiRoutesNeedWalletTokenExceptWalletCreationAndCardAuthorization() {
        String wallet = tokenWithRoles(List.of("WALLET"));
        String customer = validToken();

        client.post().uri("/api/v1/yanki/wallets")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isEqualTo(503);
        client.get().uri("/api/v1/yanki/wallet").exchange().expectStatus().isUnauthorized();
        client.get().uri("/api/v1/yanki/wallet")
                .headers(headers -> headers.setBearerAuth(wallet))
                .exchange()
                .expectStatus().isEqualTo(503);
        client.get().uri("/api/v1/yanki/wallet")
                .headers(headers -> headers.setBearerAuth(customer))
                .exchange()
                .expectStatus().isForbidden();
        client.post().uri("/api/v1/yanki/debit-card-links")
                .headers(headers -> headers.setBearerAuth(customer))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isEqualTo(503);
        client.post().uri("/api/v1/yanki/debit-card-links")
                .headers(headers -> headers.setBearerAuth(wallet))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isForbidden();
    }
}
