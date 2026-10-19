package com.fptaptech.auth.config;

import com.fptaptech.auth.service.DatabaseUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.context.SecurityContextHolderFilter;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomAuthenticationSuccessHandler successHandler;
    private final CustomAuthenticationFailureHandler failureHandler;
    private final CustomLogoutSuccessHandler logoutSuccessHandler;
    private final DatabaseUserDetailsService userDetailsService;
    private final SessionTrackingFilter sessionTrackingFilter;
    private final TwoFactorEnforcementFilter twoFactorEnforcementFilter;

    public SecurityConfig(CustomAuthenticationSuccessHandler successHandler,
                          CustomAuthenticationFailureHandler failureHandler,
                          CustomLogoutSuccessHandler logoutSuccessHandler,
                          DatabaseUserDetailsService userDetailsService,
                          SessionTrackingFilter sessionTrackingFilter,
                          TwoFactorEnforcementFilter twoFactorEnforcementFilter) {
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
        this.logoutSuccessHandler = logoutSuccessHandler;
        this.userDetailsService = userDetailsService;
        this.sessionTrackingFilter = sessionTrackingFilter;
        this.twoFactorEnforcementFilter = twoFactorEnforcementFilter;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, PersistentTokenRepository persistentTokenRepository) {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/registration", "/login", "/error", "/verify-email",
                                "/password/forgot", "/password/reset", "/invite/accept",
                                "/css/**", "/js/**", "/images/**").permitAll()
                        .requestMatchers("/admin/**", "/admin").hasRole("ADMIN")
                        .requestMatchers("/lecturer/**").hasAnyRole("LECTURER", "ADMIN")
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                        .permitAll())
                .exceptionHandling(ex -> {
                    org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint entryPoint =
                            new org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint("/login");
                    entryPoint.setFavorRelativeUris(false);
                    ex.authenticationEntryPoint(entryPoint);
                })
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(logoutSuccessHandler)
                        .permitAll())
                .rememberMe(remember -> remember
                        .tokenRepository(persistentTokenRepository)
                        .tokenValiditySeconds(14 * 24 * 3600)
                        .key("fpt-aptech-secure-remember-me-key-2026")
                        .userDetailsService(userDetailsService))
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; script-src 'self' https://cdn.jsdelivr.net"))
                )
                .addFilterAfter(sessionTrackingFilter, SecurityContextHolderFilter.class)
                .addFilterAfter(twoFactorEnforcementFilter, AuthorizationFilter.class);

        return http.build();
    }

    @Bean
    PersistentTokenRepository persistentTokenRepository(DataSource dataSource) {
        JdbcTokenRepositoryImpl repository = new JdbcTokenRepositoryImpl();
        repository.setDataSource(dataSource);
        return repository;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
