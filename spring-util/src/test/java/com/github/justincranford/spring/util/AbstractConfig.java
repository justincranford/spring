package com.github.justincranford.spring.util;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.spring.util.config.PasswordEncoderITConfig;
import com.github.justincranford.spring.util.config.PropertiesConfig;
import com.github.justincranford.spring.util.config.RestConfig;
import com.github.justincranford.spring.util.config.UserDetailsITConfig;

@TestConfiguration
//@Profile("!default")
@Import({RestConfig.class, PropertiesConfig.class, PasswordEncoderITConfig.class, UserDetailsITConfig.class})
public class AbstractConfig {
}
