package store.aurora.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;


@Component
@Slf4j
public class JwtAuthorizationHeaderFilter extends AbstractGatewayFilterFactory<JwtAuthorizationHeaderFilter.Config> {

    @Value("${spring.jwt.secret}")
    private String secretKey;

    public JwtAuthorizationHeaderFilter() {
        super(Config.class);
    }

    public static class Config {
        // application.properties 파일에서 지정한 filer의 Argument값을 받는 부분
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            log.debug("jwt-validation-filter");
            ServerHttpRequest request = exchange.getRequest();

            String path = request.getURI().getPath();

            if (path.contains("login")) {
                return chain.filter(exchange);
            }


            // Authorization 헤더가 없는 경우
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                log.error("Missing Authorization Header");
                return handleUnauthorized(exchange);
            }

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.error("Invalid Authorization Header");
                return handleUnauthorized(exchange);
            }

            // AccessToken 추출
            String token = authHeader.substring("Bearer ".length());
            log.debug("token: {}", token);

            try {
                // JWT 검증
                Claims claims = validateToken(token);

                // 검증 완료 후 사용자 정보를 Request에 추가
                exchange = exchange.mutate()
                        .request(builder -> builder.header("X-USER-ID", claims.getSubject()))
                        .build();

                log.debug("JWT validated for user: {}", claims.getSubject());

            } catch (Exception e) {
                log.error("Invalid JWT: {}", e.getMessage());
                return handleUnauthorized(exchange);
            }

            return chain.filter(exchange);
        };
    }

    private Claims validateToken(String token) {
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

