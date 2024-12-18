//package com.recommend.movie.springbootdeveloper.controller;
//
//import com.recommend.movie.springbootdeveloper.dto.CreateAccessTokenRequest;
//import com.recommend.movie.springbootdeveloper.dto.CreateAccessTokenResponse;
//import com.recommend.movie.springbootdeveloper.service.TokenService;
//import lombok.RequiredArgsConstructor;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.RequestBody;
//import org.springframework.web.bind.annotation.RestController;
//
//@RequiredArgsConstructor
//@RestController
//public class TokenApiController2 {
//
//    private final TokenService tokenService;
//
//    //post 요청이 오면 토큰 서비스에서 리프레시 토큰을 기반으로 새로운 토큰을 만든다
//    @PostMapping("/api/token")
//    public ResponseEntity<CreateAccessTokenResponse> createNewAccessToken(@RequestBody CreateAccessTokenRequest request) {
//        String newAccessToken = tokenService.createNewAccessToken(request.getRefreshToken());
//
//        return ResponseEntity.status(HttpStatus.CREATED)
//                .body(new CreateAccessTokenResponse(newAccessToken));
//    }
//}
