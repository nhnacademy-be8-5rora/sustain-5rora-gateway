package store.aurora.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import store.aurora.gateway.util.KeyDecrypt;

import java.util.List;

@Component
@Slf4j
public class JwtAuthorizationHeaderFilter extends AbstractGatewayFilterFactory<JwtAuthorizationHeaderFilter.Config> {

    private final KeyDecrypt keyDecrypt;

    private static final Logger USER_LOG = LoggerFactory.getLogger("user-logger");

    private static final List<String> AUTHENTICATION_URI = List.of("/api/users/auth/me", "/api/cart"); //인증이 필요한 uri 추가 // todo pathvariable 있는 uri는??

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

            // todo 인증이 필요하지 않은 uri는 통과
            //인증 x
            if(!AUTHENTICATION_URI.contains(path)
                    && !path.startsWith("/api/points") && !path.startsWith("/api/addresses")
                    && !path.startsWith("/api/coupon")
                    && !path.startsWith("/api/books/likes")){

                USER_LOG.debug("gateway 통과");
                return chain.filter(exchange);
            }


            //인증 o
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                if(path.startsWith("/api/cart")) {
                    log.debug("로그인 안 한 사용자 장바구니 요청");
                    return chain.filter(exchange);
                }
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

