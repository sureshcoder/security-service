package com.example.securityservice.config;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import redis.embedded.RedisServer;

import java.io.IOException;

@Configuration
public class EmbeddedRedisConfig {

    private static RedisServer redisServer;
    private static boolean started = false;

    @Value("${spring.data.redis.port}")
    private int redisPort;

    @PostConstruct
    public void start() throws IOException {
        if (!started) {
            redisServer = new RedisServer(redisPort);
            redisServer.start();
            started = true;
        }
    }

    @PreDestroy
    public void stop() throws IOException {
        if (redisServer != null && started) {
            redisServer.stop();
            started = false;
        }
    }
}
