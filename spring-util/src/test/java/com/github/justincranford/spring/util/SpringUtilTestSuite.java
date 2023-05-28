package com.github.justincranford.spring.util;

import org.junit.platform.suite.api.IncludeClassNamePatterns;
import org.junit.platform.suite.api.SelectPackages;
import org.junit.platform.suite.api.Suite;
import org.junit.platform.suite.api.SuiteDisplayName;

@SelectPackages({"com.github.justincranford.spring.util", "com.github.justincranford.spring.util.api"})
//@IncludePackages({"com.github.justincranford.spring.util"})
@IncludeClassNamePatterns({"^.*Test*$", "^.*IT*$"})

@Suite
@SuiteDisplayName("spring-util all tests")
public class SpringUtilTestSuite {
}
