//package com.recommend.movie.springbootdeveloper.config;
//
//import com.fasterxml.jackson.databind.ObjectMapper;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.http.MediaType;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.authentication.AuthenticationFailureHandler;
//import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
//
//import javax.servlet.http.HttpServletResponse;
//import java.util.HashMap;
//import java.util.Map;
//
//@Configuration
//@EnableWebSecurity
//public class WebSecurityConfig4 extends WebSecurityConfigurerAdapter {
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .antMatchers("/api/public/**", "/login").permitAll()
//                .anyRequest().authenticated()
//                .and()
//                .formLogin()
//                .loginPage("/login") // 로그인 페이지 경로
//                .loginProcessingUrl("/api/login") // 로그인 처리 URL
//                .successHandler(authenticationSuccessHandler()) // 성공 핸들러
//                .failureHandler(authenticationFailureHandler()) // 실패 핸들러
//                .permitAll()
//                .and()
//                .logout()
//                .logoutUrl("/api/logout")
//                .logoutSuccessHandler((request, response, authentication) -> {
//                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//                    response.getWriter().write("{\"message\": \"Logout successful\"}");
//                })
//                .permitAll();
//    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//
//    // 로그인 성공 시 JSON 반환
//    @Bean
//    public AuthenticationSuccessHandler authenticationSuccessHandler() {
//        return (request, response, authentication) -> {
//            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//            Map<String, Object> data = new HashMap<>();
//            data.put("message", "Login successful");
//            data.put("user", authentication.getName());
//
//            ObjectMapper objectMapper = new ObjectMapper();
//            response.getWriter().write(objectMapper.writeValueAsString(data));
//        };
//    }
//
//    // 로그인 실패 시 JSON 반환
//    @Bean
//    public AuthenticationFailureHandler authenticationFailureHandler() {
//        return (request, response, exception) -> {
//            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//            Map<String, Object> data = new HashMap<>();
//            data.put("message", "Login failed");
//            data.put("error", exception.getMessage());
//
//            ObjectMapper objectMapper = new ObjectMapper();
//            response.getWriter().write(objectMapper.writeValueAsString(data));
//        };
//    }
//}
