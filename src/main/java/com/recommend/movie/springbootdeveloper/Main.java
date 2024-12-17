package com.recommend.movie;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@EnableJpaAuditing
@EntityScan(basePackages = "com.recommend.movie.springbootdeveloper.domain")  // 엔티티 패키지 명시
@EnableJpaRepositories(basePackages = "com.recommend.movie.springbootdeveloper.repository")
@SpringBootApplication(exclude = {
        org.springframework.boot.autoconfigure.h2.H2ConsoleAutoConfiguration.class
})
public class Main {
    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
        System.out.println("==========================SVT FOREVER");

//        for (int i = 1; i <= 5; i++) {
//            //TIP <shortcut actionId="Debug"/>을(를) 눌러 코드 디버그를 시작하세요. 1개의 <icon src="AllIcons.Debugger.Db_set_breakpoint"/> 중단점을 설정해 드렸습니다
//            // 언제든 <shortcut actionId="ToggleLineBreakpoint"/>을(를) 눌러 중단점을 더 추가할 수 있습니다.
//            System.out.println("i = " + i);
//        }
    }
}