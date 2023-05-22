package com.github.justincranford.spring.util.config;

import java.util.Map;
import java.util.TreeMap;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;

@TestConfiguration
//@Profile("!default")
public class PropertiesITConfig {
	@Bean
	public Map<String, Object> allProperties(final Environment environment) {
	    final Map<String, Object> map = new TreeMap<>();
	    if (environment instanceof ConfigurableEnvironment) {
	        for (PropertySource<?> propertySource : ((ConfigurableEnvironment) environment).getPropertySources()) {
	            if (propertySource instanceof EnumerablePropertySource) {
	                for (String key : ((EnumerablePropertySource<?>) propertySource).getPropertyNames()) {
	                    map.put(key, propertySource.getProperty(key));
	                }
	            }
	        }
	    }
	    return map;
	}
}