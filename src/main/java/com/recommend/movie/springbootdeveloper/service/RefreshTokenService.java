package com.recommend.movie.springbootdeveloper.service;

import com.recommend.movie.springbootdeveloper.domain.RefreshToken;
import com.recommend.movie.springbootdeveloper.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

//    //전달받은 리프레시 토큰으로 토큰 객체를 검색해서 전달
//    public RefreshToken findByRefreshToken(String refreshToken) {
//        return refreshTokenRepository.findByRefreshToken(refreshToken)
//                .orElseThrow(() -> new IllegalArgumentException("Unexpected token"));
//    }


    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenService.class);

    public RefreshToken findByRefreshToken(String refreshToken) {
        logger.info("Searching for refreshToken: " + refreshToken);  // 로그 출력
        return refreshTokenRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> {
                    logger.error("No token found for: " + refreshToken);  // 예외 발생 시 로그 출력
                    return new IllegalArgumentException("Unexpected token");
                });
    }
}

