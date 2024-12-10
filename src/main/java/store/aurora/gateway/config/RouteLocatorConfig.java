package store.aurora.gateway.config;


import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import store.aurora.gateway.filter.JwtAuthorizationHeaderFilter;

@Configuration
@RequiredArgsConstructor
public class RouteLocatorConfig {

    private final JwtAuthorizationHeaderFilter jwtAuthorizationHeaderFilter;

    @Bean
    public RouteLocator myRoute(RouteLocatorBuilder builder) {

        RouteLocator routeLocator =  builder.routes().build();


        return builder.routes()
                .route("account-api",
                        p->p.path("/api/users/**")
                                .filters(f->f.filter(jwtAuthorizationHeaderFilter.apply(new JwtAuthorizationHeaderFilter.Config())))
                                .uri("lb://ACCOUNT-SERVICE")
                )
                .route("book-api",
                        p -> p.path("/api/books/**").and()
                                .uri("lb://SHOPPINGMALL-SERVICE"))
                .build();
    }
}
// /api/books/~~
// /api/orders/~~