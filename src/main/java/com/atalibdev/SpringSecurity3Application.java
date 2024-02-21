package com.atalibdev;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.File;

import static com.atalibdev.constant.FileConstant.USER_FOLDER;

@SpringBootApplication
public class SpringSecurity3Application {
    public static void main(String[] args) {
        SpringApplication.run(SpringSecurity3Application.class, args);
        new File(USER_FOLDER).mkdirs();
    }
}
