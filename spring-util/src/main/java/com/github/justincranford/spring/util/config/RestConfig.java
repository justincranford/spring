package com.github.justincranford.spring.util.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;

@Lazy
@Configuration
public class RestConfig {
	@Bean
	public String baseUrl(
		@Value(value="${server.ssl.enabled:false}")             final boolean serverSslEnabled,
	    @Value(value="${server.ssl.auto-config.enabled:false}") final boolean serverSslAutoConfigEnabled,
	    @Value(value="${server.address}")                       final String  serverAddress,
	    @Value(value="${local.server.port}")                    final int     localServerPort
	) throws Exception {
	    final boolean useHttps = serverSslEnabled || serverSslAutoConfigEnabled;
	    final String baseUrl = (useHttps ? "https" : "http") + "://" + serverAddress + ":" + localServerPort;
		return baseUrl;
	}
}