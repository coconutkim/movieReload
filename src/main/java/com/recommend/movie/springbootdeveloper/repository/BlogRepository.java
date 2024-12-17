package com.recommend.movie.springbootdeveloper.repository;

import com.recommend.movie.springbootdeveloper.domain.Article;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BlogRepository extends JpaRepository<Article, Long> {
}

