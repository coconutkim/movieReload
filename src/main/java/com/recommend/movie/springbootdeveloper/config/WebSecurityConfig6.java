//package com.recommend.movie.springbootdeveloper.config;
//
//import com.devonfw.module.security.common.impl.rest.JsonUsernamePasswordAuthenticationFilter;
//import com.recommend.movie.springbootdeveloper.service.UserDetailService;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.RequiredArgsConstructor;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
//
//@RequiredArgsConstructor
//@Configuration
//public class WebSecurityConfig6 {
//
//    private final UserDetailService userService;
//
//    /**
//     * 비밀번호를 암호화하기 위한 BCryptPasswordEncoder Bean 등록
//     */
//    @Bean
//    public BCryptPasswordEncoder bCryptPasswordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//
//    /**
//     * 인증 관리 Bean 설정
//     */
//    @Bean
//    public AuthenticationManager authenticationManager(HttpSecurity http, BCryptPasswordEncoder bCryptPasswordEncoder) throws Exception {
//        return http.getSharedObject(AuthenticationManagerBuilder.class)
//                .userDetailsService(userService)
//                .passwordEncoder(bCryptPasswordEncoder)
//                .and()
//                .build();
//    }
//
//    /**
//     * 보안 필터 체인 설정
//     */
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        return http
//                .csrf().disable() // CSRF 비활성화 (REST API는 불필요)
//                .formLogin().disable() // 폼 로그인 비활성화
//                .httpBasic().disable() // HTTP 기본 인증 비활성화
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/login", "/signup", "/user", "/articles", "/api/token").permitAll() // 공개 URL
//                        .anyRequest().authenticated() // 나머지 요청은 인증 필요
//                )
////                .exceptionHandling(exception -> exception
////                        .authenticationEntryPoint((request, response, authException) -> {
////                            // 인증되지 않은 사용자가 접근 시 JSON 응답
////                            response.setContentType("application/json");
////                            response.setCharacterEncoding("UTF-8");
////                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//////                            response.getWriter().write("{\"메세지\": \"Unauthorized\"}");
////
////                            // 예외의 메시지를 포함한 JSON 응답 생성
////                            String errorMessage = authException.getMessage() != null ? authException.getMessage() : "Unknown error";
////
////                            response.getWriter().write("{\"메세지\": \"Unauthorized\", \"error\": \"" + errorMessage + "\"}");
////                        })
////                )
////                .addFilterAt(jsonLoginFilter(), UsernamePasswordAuthenticationFilter.class) // 커스텀 JSON 로그인 필터 추가
//
//
//
//
//                .exceptionHandling(exception -> exception
//                        .authenticationEntryPoint((request, response, authException) -> {
//                            // 인증되지 않은 사용자가 접근 시 JSON 응답
//                            response.setContentType("application/json");
//                            response.setCharacterEncoding("UTF-8");
//                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//
//                            // Authorization 헤더에서 토큰을 추출
//                            String authorizationHeader = request.getHeader("Authorization");
//
//                            // Authorization 헤더가 없거나 Bearer 접두어가 없는 경우
//                            if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
//                                response.getWriter().write("{\"메세지\": \"Unauthorized\", \"error\": \"Missing or invalid Authorization header\"}");
//                                return;
//                            }
//
//                            // Authorization 헤더에서 토큰만 추출
//                            String token = authorizationHeader.substring(7);
//
//                            // TokenProvider를 통해 토큰의 유효성 검증
//                            try {
//                                if (tokenProvider.validToken(token)) {
//                                    // 토큰이 유효하면 인증을 설정
//                                    Authentication authentication = tokenProvider.getAuthentication(token);
//                                    SecurityContextHolder.getContext().setAuthentication(authentication);
//                                    response.getWriter().write("{\"메세지\": \"Unauthorized\", \"error\": \"Invalid or expired token\"}");
//                                } else {
//                                    response.getWriter().write("{\"메세지\": \"Unauthorized\", \"error\": \"Invalid or expired token\"}");
//                                }
//                            } catch (Exception e) {
//                                // 토큰 검증 시 예외 발생 시 처리
//                                response.getWriter().write("{\"메세지\": \"Unauthorized\", \"error\": \"" + e.getMessage() + "\"}");
//                            }
//                        })
//                )
//                .addFilterAt(tokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
//                .build();
//    }
//
//    /**
//     * JSON 기반 로그인 필터 추가
//     */
//    public JsonUsernamePasswordAuthenticationFilter jsonLoginFilter() {
//        //사용자 이름과 비밀번호를 json 형식으로 받아 인증
//        JsonUsernamePasswordAuthenticationFilter filter = new JsonUsernamePasswordAuthenticationFilter(new AntPathRequestMatcher("/api/token")); //RequestMatcher 타입의 인자를 받아야 한다
//        //로그인 경로에 대해서만 필터가 동작
//        filter.setAuthenticationManager(authentication -> {
//            // 사용자 인증 로직
//            String username = (String) authentication.getPrincipal();
//            String password = (String) authentication.getCredentials();
//            try {
//                return authenticationManagerBean().authenticate(
//                        new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(username, password)
//                );
//            } catch (Exception e) {
//                throw new RuntimeException(e);
//            }
//        });
//
//        filter.setAuthenticationSuccessHandler((request, response, authentication) -> {
//            // 인증 성공 시 JSON 응답
//            response.setContentType("application/json");
//            response.setCharacterEncoding("UTF-8");
//            response.setStatus(HttpServletResponse.SC_OK);
//            response.getWriter().write("{\"message\": \"Login successful\"}");
//        });
//
//        filter.setAuthenticationFailureHandler((request, response, exception) -> {
//            // 인증 실패 시 JSON 응답
//            response.setContentType("application/json");
//            response.setCharacterEncoding("UTF-8");
//            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//            response.getWriter().write("{\"message\": \"Unauthorized\", \"error\": \"" + exception.getMessage() + "\"}");
//        });
//
//        return filter;
//    }
//
//    /**
//     * AuthenticationManager Bean 생성 (JSON 필터에서 사용)
//     */
//    @Bean
//    public AuthenticationManager authenticationManagerBean() throws Exception {
//        return authenticationManager(null, bCryptPasswordEncoder());
//    }
//}
