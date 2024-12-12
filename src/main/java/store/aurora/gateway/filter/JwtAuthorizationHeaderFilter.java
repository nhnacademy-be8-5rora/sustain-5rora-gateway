package store.aurora.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import store.aurora.gateway.util.KeyDecrypt;

@Component
@Slf4j
public class JwtAuthorizationHeaderFilter extends AbstractGatewayFilterFactory<JwtAuthorizationHeaderFilter.Config> {

    private final KeyDecrypt keyDecrypt;

//    @Value("${spring.jwt.secret}")
//    private String secretKey;


    public JwtAuthorizationHeaderFilter(KeyDecrypt keyDecrypt) {
        super(Config.class);
        this.keyDecrypt = keyDecrypt;
    }

    @Getter
    @Setter
    public static class Config {
        private String secretKey;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            log.debug("jwt-validation-filter");
            log.debug("config-secretKey: {}", config.getSecretKey());
            ServerHttpRequest request = exchange.getRequest();

            String path = request.getURI().getPath();

            if (path.contains("login")) {
                return chain.filter(exchange);
            }


            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                log.error("Missing Authorization Header");
                return handleUnauthorized(exchange);
            }

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.error("Invalid Authorization Header");
                return handleUnauthorized(exchange);
            }

            String token = authHeader.substring("Bearer ".length());
            log.debug("token: {}", token);


            try {
                Claims claims = validateToken(token, config.getSecretKey());
                log.debug("claims-name: {}", claims.get("username"));


                String decryptKey = keyDecrypt.decrypt((String) claims.get("username"));
                log.debug("decryptKey: {}", decryptKey);


                exchange = exchange.mutate()
                        .request(builder -> builder.header("X-USER-ID", decryptKey))
                        .build();

                log.debug("JWT validated for user: {}", claims.getSubject());

            } catch (Exception e) {
                log.error("Invalid JWT: {}", e.getMessage());
                return handleUnauthorized(exchange);
            }

            return chain.filter(exchange);
        };
    }

    private Claims validateToken(String token, String secretKey) {
        return Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Mono<Void> handleUnauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }
}

