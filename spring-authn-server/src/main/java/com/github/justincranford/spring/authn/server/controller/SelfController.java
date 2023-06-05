package com.github.justincranford.spring.authn.server.controller;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.security.Principal;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.github.justincranford.spring.util.model.User;
import com.github.justincranford.spring.util.util.JsonUtil;

@CrossOrigin(origins={"https://localhost:8443"})
@RestController
@RequestMapping(path="/api", produces={APPLICATION_JSON_VALUE})
public class SelfController {
	@SuppressWarnings("unused")
	private Logger logger = LoggerFactory.getLogger(SelfController.class);

	//////////////////////////////////////////////////////////////////////////////////////////////////////////

	@GetMapping(path = "/self1")
	public String getBuildInUser(final Principal principal) {
		// UsernamePasswordAuthenticationToken > AbstractAuthenticationToken > Authentication+CredentialsContainer > Principal
		final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		final String principalStr = (principal instanceof User bu) ? bu.toString() : authentication.getPrincipal().toString();
		return JsonUtil.pojoToJsonString(
			Map.of(
				"name", authentication.getName(),
				"authorities", authentication.getAuthorities().toString(),
				"details", authentication.getDetails().toString(),
				"principal", principalStr
			)
		);
	}
	// TODO
//	@GetMapping(path = "/self2")
//	public String getOAuth2User(@AuthenticationPrincipal OAuth2User principal) {
//		if (principal == null) {
//			throw new UsernameNotFoundException("OAuth2User not found");
//		}
//		// OAuth2User > OAuth2AuthenticatedPrincipal > AuthenticatedPrincipal
//		// DefaultOidcUser extends DefaultOAuth2User(OAuth2User) implements OidcUser(OAuth2User, IdTokenClaimAccessor,OAuth2AuthenticatedPrincipal,AuthenticatedPrincipal)
//		return JSONObject.toJSONString(principal.getAttributes());
//	}
}