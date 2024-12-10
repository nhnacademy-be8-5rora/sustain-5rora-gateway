package store.aurora.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
@Slf4j
public class JwtAuthorizationHeaderFilter extends AbstractGatewayFilterFactory<JwtAuthorizationHeaderFilter.Config> {

    public JwtAuthorizationHeaderFilter(){
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

            //TODO#3-1 Header에 Authorization 존재하지 않는다면 적절한 예외처리
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authorization header is missing");
            }

            String token = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (token == null || !token.startsWith("Bearer ")) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token format");
            }

            String accessToken = token.substring(7); // "Bearer " 이후의 부분만 가져옴

            try {
                //TODO#3-2 AccessToken 검증
                String secretKey = "Ny0pm2CWIAST07ElsTAVZgCqJKJd2bE9lpKyewuOhyyKoBApt1Ny0pm2CWIAST07ElsTAVZgCqJKJd2bE9lpKyewuOhyyKoBApt1";
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)))
                        .build()
                        .parseClaimsJws(accessToken)
                        .getBody();

                // Token이 만료되었는지 확인
                if (claims.getExpiration().before(new Date())) {
                    throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token is expired");
                }

                // TODO: 로그아웃된 토큰 확인 (Black List에서 조회)
                // BlacklistService.isBlacklisted(accessToken);

                //TODO#3-3 검증 완료 후 Header에 X-USER-ID 추가
                String userId = claims.getSubject(); // JWT에서 Subject를 userId로 사용
                exchange = exchange.mutate().request(builder -> builder.header("X-USER-ID", userId)).build();

            } catch (JwtException e) {
                log.error("Invalid JWT token: {}", e.getMessage());
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token");
            }

            return chain.filter(exchange);
        };
    }


}
