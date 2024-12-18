package com.recommend.movie.springbootdeveloper.controller;

import com.recommend.movie.springbootdeveloper.dto.CreateAccessTokenRequest;
import com.recommend.movie.springbootdeveloper.dto.CreateAccessTokenResponse;
import com.recommend.movie.springbootdeveloper.service.TokenService;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class TokenApiController {

    private final TokenService tokenService;

//    //post 요청이 오면 토큰 서비스에서 리프레시 토큰을 기반으로 새로운 토큰을 만든다
//    @PostMapping("/api/token")
//    public ResponseEntity<CreateAccessTokenResponse> createNewAccessToken(
//            @ModelAttribute CreateAccessTokenRequest request) { //폼 데이터를 처리하도록
//
//        String newAccessToken = tokenService.createNewAccessToken(request.getRefreshToken());
//
//        return ResponseEntity.status(HttpStatus.CREATED)
//                .body(new CreateAccessTokenResponse(newAccessToken));
//    }

    @PostMapping("/api/token")
    public ResponseEntity<CreateAccessTokenResponse> createNewAccessToken(@RequestBody CreateAccessTokenRequest request) {
        // 리프레시 토큰을 사용하여 새로운 액세스 토큰 생성
        String newAccessToken = tokenService.createNewAccessToken(request.getRefreshToken());

        // 생성된 액세스 토큰을 응답으로 반환
        CreateAccessTokenResponse response = new CreateAccessTokenResponse(newAccessToken);

        // JSON 응답 반환
        return ResponseEntity.status(HttpStatus.OK)
                .body(new CreateAccessTokenResponse(newAccessToken));  // OK 상태로 응답
    }

}
