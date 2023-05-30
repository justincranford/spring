package com.github.justincranford.spring.authn.server.model;

import java.util.LinkedHashSet;
import java.util.Set;

public class SimpleGrantedAuthorityNames {
    public static final Set<String> NAMES = new LinkedHashSet<>();

    public static final String ROLE_OPS_ADMIN = register("ROLE_OPS_ADMIN");
    public static final String ROLE_OPS_USER  = register("ROLE_OPS_USER");
    public static final String ROLE_APP_ADMIN = register("ROLE_APP_ADMIN");
    public static final String ROLE_APP_USER  = register("ROLE_APP_USER");
    public static final String OAUTH2_USER    = register("OAUTH2_USER");
    public static final String OIDC_USER      = register("OIDC_USER");

    public static String register(String name) {
    	NAMES.add(name);
    	return name;
    }
}
