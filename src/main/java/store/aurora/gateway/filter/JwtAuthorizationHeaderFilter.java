package store.aurora.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
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
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import store.aurora.gateway.util.KeyDecrypt;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
@Slf4j
public class JwtAuthorizationHeaderFilter extends AbstractGatewayFilterFactory<JwtAuthorizationHeaderFilter.Config> {

    public static final String REFRESH_TOKEN = "refresh";
    public static final String USERNAME = "username";

    private static final List<String> AUTHENTICATION_URI = List.of("/api/users/auth/me", "/api/books/search", "/api/auth/refresh"); //인증이 필요한 uri 추가 // todo pathvariable 있는 uri는??

    public JwtAuthorizationHeaderFilter() {
        super(Config.class);
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
                    && !path.startsWith("/api/points/history") && !path.startsWith("/api/addresses") && !path.startsWith("/api/cart")
                    && !path.startsWith("/api/coupon")
                    && !path.startsWith("/api/books/likes")
            ){

                log.debug("gateway 통과");
                return chain.filter(exchange);
            }

            // access 토큰 재발급 요청인 경우
            if (path.equals("/api/auth/refresh")) {
                if (!request.getHeaders().containsKey(REFRESH_TOKEN)) {
                    log.error("Missing {} Header", REFRESH_TOKEN);
                    return handleUnauthorized(exchange);
                }

                String refreshToken = request.getHeaders().getFirst(REFRESH_TOKEN);

                if (refreshToken == null) {
                    log.error("Invalid {} Header", REFRESH_TOKEN);
                    return handleUnauthorized(exchange);
                }

                try {
                    // 1. 검증 (토큰 만료 여부도 확인)
                    Claims claims = validateToken(refreshToken, config.getSecretKey());
                    log.debug("claims-name: {}", claims.get(USERNAME));

                    String decryptKey = KeyDecrypt.decrypt((String) claims.get(USERNAME));
                    log.debug("decryptKey: {}", decryptKey);

                    exchange = exchange.mutate()
                            .request(builder -> builder.header("X-USER-ID", decryptKey))
                            .build();

                    log.debug("refresh token validated for user: {}", claims.getSubject());
                    return chain.filter(exchange);
                } catch (ExpiredJwtException e) {
                    log.info("refresh token expired: {}", e.getMessage());
                } catch (Exception e) {
                    log.error("access 토큰 재발급 중 에러 발생 : {}", e.getMessage());
                }
                return handleUnauthorized(exchange);
            }

            //인증 o
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                if (path.startsWith("/api/coupon/shop")
                    || path.startsWith("/api/coupon/admin")
                    || path.startsWith("/api/coupon/signup/welcome")
                    || path.startsWith("/api/cart")
                    || path.startsWith("/api/books/search")
                        || path.startsWith("/api/coupon/welcome")
                ) {
                    log.debug("로그인 안 한 사용자가 {} 요청", path);
                    return chain.filter(exchange);
                }

                log.error("Missing {} Header", HttpHeaders.AUTHORIZATION);
                return handleUnauthorized(exchange);
            }

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.error("Invalid Authorization Header");
                return handleUnauthorized(exchange);
            }

            String token = authHeader.substring("Bearer ".length());
            log.debug("token: {}", token);

            // authorization 토큰 (=access 토큰)을 user id 로 변환
            try {
                Claims claims = validateToken(token, config.getSecretKey());
                log.debug("claims-name: {}", claims.get(USERNAME));

                String decryptKey = KeyDecrypt.decrypt((String) claims.get(USERNAME));
                log.debug("decryptKey: {}", decryptKey);

                exchange = exchange.mutate()
                        .request(builder -> builder.header("X-USER-ID", decryptKey))
                        .build();

                log.debug("access token validated for user: {}", claims.getSubject());
                return chain.filter(exchange);
            } catch (ExpiredJwtException e) {
                log.info("Expired JWT: {}", e.getMessage());
                // ExpiredJwtException 처리 - 440 Login Timeout 사용
                return handleUnauthorized(exchange, e.getMessage());
            } catch (Exception e) {
                log.error("Invalid access token: {}", e.getMessage(), e);
                return handleUnauthorized(exchange);
            }
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

    private Mono<Void> handleUnauthorized(ServerWebExchange exchange, String errorMessage) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // JSON 응답 데이터 생성
        Map<String, String> errorDetails = new HashMap<>();
        errorDetails.put("error", "Unauthorized");
        errorDetails.put("message", errorMessage);

        try {
            // JSON 변환
            byte[] responseBytes = new ObjectMapper().writeValueAsBytes(errorDetails);
            return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                    .bufferFactory()
                    .wrap(responseBytes)));
        } catch (Exception e) {
            return exchange.getResponse().setComplete();
        }
    }
}