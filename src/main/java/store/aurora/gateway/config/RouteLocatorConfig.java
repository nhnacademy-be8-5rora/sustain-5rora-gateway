package store.aurora.gateway.config;


import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RouteLocatorConfig {

    @Bean
    public RouteLocator myRoute(RouteLocatorBuilder builder) {

        RouteLocator routeLocator =  builder.routes().build();


        return builder.routes()
                .route("account-api",
                        p->p.path("/api/users/**").and()
                                .uri("lb://ACCOUNT-SERVICE")
                )
                .route("book-api",
                        p -> p.path("/api/books/**").and()
                                .uri("lb://BOOK-SERVICE"))
                .build();
    }
}
