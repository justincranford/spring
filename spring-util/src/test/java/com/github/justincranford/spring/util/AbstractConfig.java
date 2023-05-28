package com.github.justincranford.spring.util;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.spring.util.config.PasswordEncoderITConfig;
import com.github.justincranford.spring.util.config.PropertiesITConfig;
import com.github.justincranford.spring.util.config.RestITConfig;
import com.github.justincranford.spring.util.config.UserDetailsITConfig;

@TestConfiguration
//@Profile("!default")
//@AnnotationDrivenConfig
@Import({RestITConfig.class, PropertiesITConfig.class, PasswordEncoderITConfig.class, UserDetailsITConfig.class})
public class AbstractConfig {
}
