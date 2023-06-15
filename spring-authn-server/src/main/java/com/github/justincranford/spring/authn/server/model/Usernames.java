package com.github.justincranford.spring.authn.server.model;

import java.util.Collections;
import java.util.List;

public class Usernames {
	public static final String OPSADMIN = "opsadmin";
	public static final String OPSUSER = "opsuser";
	public static final String APPADMIN = "appadmin";
	public static final String APPUSER = "appuser";
	public static final List<String> WELL_KNOWN = Collections.unmodifiableList(List.of(OPSADMIN, OPSUSER, APPADMIN, APPUSER));
}
