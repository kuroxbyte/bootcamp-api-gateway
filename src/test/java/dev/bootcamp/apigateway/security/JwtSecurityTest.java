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

/**
 * Seguridad del gateway: rutas públicas, 401 sin token o con un token inválido, y paso de las
 * peticiones con un token válido (sin servicios registrados responden 503 por el circuit breaker).
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
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keys.getPublic())
                .privateKey((RSAPrivateKey) keys.getPrivate())
                .build();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject("c1")
                .issuedAt(expiresAt.minusSeconds(3600))
                .expiresAt(expiresAt)
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
}
