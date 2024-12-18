package com.recommend.movie.springbootdeveloper.config;

import com.devonfw.module.security.common.impl.rest.JsonUsernamePasswordAuthenticationFilter;
import com.recommend.movie.springbootdeveloper.config.jwt.TokenProvider;
import com.recommend.movie.springbootdeveloper.service.UserDetailService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@RequiredArgsConstructor
@Configuration
public class WebSecurityConfig {

    private final UserDetailService userService;

    /**
     * 비밀번호를 암호화하기 위한 BCryptPasswordEncoder Bean 등록
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 인증 관리 Bean 설정
     */
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(userService)
                .passwordEncoder(bCryptPasswordEncoder())
                .and()
                .build();
    }

    /**
     * 보안 필터 체인 설정
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, TokenProvider tokenProvider) throws Exception {

        AuthenticationManager authenticationManager = authenticationManager(http);

        return http
                .csrf().disable() // CSRF 비활성화 (REST API는 불필요)
                .cors().configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(List.of("http://localhost:3000")); // 허용할 클라이언트 도메인
                    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
                    config.setAllowedHeaders(List.of("*"));
                    return config;
                })
                .and()
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/signup", "/user", "/articles", "/api/token").permitAll() // 공개 URL
                        .anyRequest().authenticated() // 나머지 요청은 인증 필요
                )
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint((request, response, authException) -> {
                            // 인증되지 않은 사용자가 접근 시 JSON 응답
                            response.setContentType("application/json");
                            response.setCharacterEncoding("UTF-8");
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            response.getWriter().write("{\"message\": \"Unauthorized\"}");
                        })
                )
//                .addFilterBefore(new TokenAuthenticationFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class) // JWT 인증 필터 추가
//                .addFilterAt(jsonLoginFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class) // 커스텀 JSON 로그인 필터 추가

                // 먼저 JSON 로그인 필터를 추가하여 비밀번호를 해싱한 값을 비교
                .addFilterAt(jsonLoginFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class) // 커스텀 JSON 로그인 필터 추가
                // 그 다음 JWT 인증 필터를 추가
                .addFilterBefore(new TokenAuthenticationFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class) // JWT 인증 필터 추가
                .build();
    }

    /**
     * JSON 기반 로그인 필터 추가
     */
    public JsonUsernamePasswordAuthenticationFilter jsonLoginFilter(AuthenticationManager authenticationManager) {
        JsonUsernamePasswordAuthenticationFilter filter = new JsonUsernamePasswordAuthenticationFilter(new AntPathRequestMatcher("/api/token"));
        filter.setAuthenticationManager(authenticationManager);

        filter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            // 인증 성공 시 JSON 응답
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().write("{\"message\": \"Login successful\"}");
        });

        filter.setAuthenticationFailureHandler((request, response, exception) -> {
            // 인증 실패 시 JSON 응답
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"message\": \"Unauthorized\", \"error\": \"" + exception.getMessage() + "\"}");
        });

        return filter;
    }
}