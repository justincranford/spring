package com.github.justincranford.spring.util.controller;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.APPLICATION_XML_VALUE;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.github.justincranford.spring.util.model.Uptime;
import com.github.justincranford.spring.util.util.JsonUtil;

@CrossOrigin(origins={"https://127.0.0.1:8443"})
@RestController
@RequestMapping(path="/api", produces={APPLICATION_JSON_VALUE,APPLICATION_XML_VALUE})
public class UptimeController {

    Logger logger = LoggerFactory.getLogger(UptimeController.class);

    @Autowired
    public Uptime.Factory uptimeFactory;

    @GetMapping(path = "/uptime")
    public Uptime uptime() {
    	final Uptime uptime = uptimeFactory.getObject();
        final String uptimeJsonString = JsonUtil.pojoToJsonString(uptime);
		this.logger.info(uptimeJsonString);
		return uptime;
    }
}