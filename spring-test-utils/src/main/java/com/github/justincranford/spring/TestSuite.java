package com.github.justincranford.spring;

import org.junit.platform.suite.api.IncludeClassNamePatterns;
import org.junit.platform.suite.api.SelectPackages;
import org.junit.platform.suite.api.Suite;
import org.junit.platform.suite.api.SuiteDisplayName;

@SelectPackages({"com.github.justincranford.spring"})
@IncludeClassNamePatterns({"./*Test", "./*Tests", ".*IT", ".*ITs"})

@Suite
@SuiteDisplayName("All tests")
public class TestSuite {
}
