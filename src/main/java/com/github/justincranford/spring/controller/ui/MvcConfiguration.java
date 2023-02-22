package com.github.justincranford.spring.controller.ui;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

//@EnableWebMvc
@Configuration
public class MvcConfiguration implements WebMvcConfigurer {
	// See WebMvcAutoConfiguration
	public void addViewControllers(final ViewControllerRegistry registry) {
//		registry.addRedirectViewController("/", "/index.html");		// FAILS
//		registry.addRedirectViewController("/", "index.html");		// FAILS
//		registry.addRedirectViewController("/", "/index");			// WORKS
//		registry.addRedirectViewController("/", "index");			// WORKS

//		registry.addViewController("/").setViewName("/index.html");	// WORKS
//		registry.addViewController("/").setViewName("index.html");	// WORKS
//		registry.addViewController("/").setViewName("/index");		// WORKS
		registry.addViewController("/").setViewName("index");		// WORKS (PREFERRED)

		registry.addViewController("/index").setViewName("index");
		registry.addViewController("/signin").setViewName("signin");
//		registry.addViewController("/error").setViewName("error");
		registry.addViewController("/logout").setViewName("redirect:/");
	}

//    @Override
//    public void configureViewResolvers(ViewResolverRegistry registry) {
//        registry.jsp("/WEB-INF/views/", ".jsp");
//    }
//
//    @Bean
//	public ViewResolver viewResolver() {
//		InternalResourceViewResolver bean = new InternalResourceViewResolver();
//
//		bean.setViewClass(JstlView.class);
//		bean.setPrefix("/WEB-INF/view/");
//		bean.setSuffix(".jsp");
//
//		return bean;
//	}
}