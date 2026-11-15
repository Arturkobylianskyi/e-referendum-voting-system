package ereferendum.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Spring Security configuration enforcing Keycloak JWT role-based access control
 * while keeping ballot submission and public ledger auditing anonymous
 */
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http.csrf(AbstractHttpConfigurer::disable);

        http.authorizeHttpRequests(auth ->{
            auth.requestMatchers(HttpMethod.POST, "/api/referendums").hasRole("ADMIN");
            auth.requestMatchers(HttpMethod.POST, "/api/referendums/*/close").hasRole("ADMIN");
            auth.requestMatchers(HttpMethod.POST, "/api/referendums/*/authorize").hasRole("VOTER");
            auth.anyRequest().permitAll();
        });

        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter(){
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(this::extractRoles);

        return converter;
    }

    private Collection<GrantedAuthority> extractRoles(Jwt jwt){
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
        if(realmAccess == null || !(realmAccess.get("roles") instanceof Collection<?> roles)){
            return List.of();
        }

        List<GrantedAuthority> authorities = new ArrayList<>();
        for(Object role : roles){
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
        }

        return authorities;
    }
}
