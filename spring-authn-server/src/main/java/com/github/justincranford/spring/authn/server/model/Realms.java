package com.github.justincranford.spring.authn.server.model;

import java.util.Collections;
import java.util.List;

public class Realms {
	public static final String OPS = "ops";
	public static final String APP = "app";
	public static final List<String> WELL_KNOWN = Collections.unmodifiableList(List.of(OPS, APP));
}
