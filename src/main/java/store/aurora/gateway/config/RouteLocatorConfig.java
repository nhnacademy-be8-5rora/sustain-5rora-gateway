package store.aurora.gateway.config;


import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import store.aurora.gateway.filter.JwtAuthorizationHeaderFilter;

//@Configuration
@RequiredArgsConstructor
public class RouteLocatorConfig {

//    private final JwtAuthorizationHeaderFilter jwtAuthorizationHeaderFilter;
//
//    @Bean
//    public RouteLocator myRoute(RouteLocatorBuilder builder) {
//
//        RouteLocator routeLocator =  builder.routes().build();
//
//        return builder.routes()
//                .route("authentication-api",
//                        p->p.path("/api/auth/**")
//                                .uri("lb://AUTHENTICATION-API")
//                )
//                .route("shop-api",
//                        p -> p.path("/api/test/**")
//                                .filters(f->f.filter(jwtAuthorizationHeaderFilter.apply(new JwtAuthorizationHeaderFilter.Config())))
//                                .uri("lb://SHOP-API"))
//                .build();
//    }
}