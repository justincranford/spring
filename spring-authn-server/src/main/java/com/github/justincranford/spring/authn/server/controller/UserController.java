package com.github.justincranford.spring.authn.server.controller;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.github.justincranford.spring.authn.server.model.UserCrudRepository;
import com.github.justincranford.spring.authn.server.model.UserNotFoundException;
import com.github.justincranford.spring.authn.server.model.WellKnownUsers;
import com.github.justincranford.spring.util.model.User;

import springfox.documentation.annotations.ApiIgnore;

@CrossOrigin(origins={"https://127.0.0.1:8443"})
@RestController
@RequestMapping(path="/api", produces={APPLICATION_JSON_VALUE})
public class UserController {
	@Autowired
	private UserCrudRepository userCrudRepository;

	@Autowired
	private WellKnownUsers wellKnownUsers;

	// TODO @PatchMapping

	//////////////////////////////////////////////////////////////////////////////////////////////////////////

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN'})")
	@PostMapping(path = "/user", consumes = { APPLICATION_JSON_VALUE })
	@ResponseStatus(HttpStatus.CREATED)
	public User create(@RequestBody final User user, @RequestParam @ApiIgnore final Map<String, String> allRequestParams) {
		return this.userCrudRepository.save(user);
	}

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN','OPS_USER'})")
	@GetMapping(path = "/user")
	public User read(@RequestParam(name = "id", required=true) final Long id, @RequestParam @ApiIgnore final Map<String, String> allRequestParams) {
		return this.userCrudRepository.findById(id).orElseThrow(UserNotFoundException::new);
	}

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN'})")
	@PutMapping(path = "/user", consumes = { APPLICATION_JSON_VALUE })
	public User update(@RequestBody final User user, @RequestParam @ApiIgnore final Map<String, String> allRequestParams) {
		this.userCrudRepository.findById(user.getId()).orElseThrow(UserNotFoundException::new);
		return this.userCrudRepository.save(user);
	}

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN'})")
	@DeleteMapping(path = "/user")
	public User delete(@RequestParam(name = "id", required=true) final Long id, @RequestParam @ApiIgnore final Map<String, String> allRequestParams) {
		final User user = this.userCrudRepository.findById(id).orElseThrow(UserNotFoundException::new);
		this.userCrudRepository.deleteById(id);
		return user;
	}

	//////////////////////////////////////////////////////////////////////////////////////////////////////////

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN'})")
	@PostMapping(path = "/users", consumes = { APPLICATION_JSON_VALUE })
	@ResponseStatus(HttpStatus.CREATED)
	public List<User> creates(@RequestBody final Iterable<User> users, @RequestParam @ApiIgnore final Map<String, String> allRequestParams) {
		return this.userCrudRepository.saveAll(users);
	}

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN','OPS_USER'})")
	@GetMapping(path = "/users")
	public List<User> reads(@RequestParam(name = "id", required=false) final List<Long> ids, @RequestParam @ApiIgnore final Map<String, String> allRequestParams) {
		if ((ids == null) || (ids.isEmpty())) {
			return this.userCrudRepository.findAll();
		}
		final List<User> users = this.userCrudRepository.findAllById(ids);
		if ((users == null) || (users.isEmpty())) {
			throw new UserNotFoundException();
		}
		return users;
	}

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN'})")
	@PutMapping(path = "/users", consumes = { APPLICATION_JSON_VALUE })
	public List<User> updates(@RequestBody final Iterable<User> users, @RequestParam @ApiIgnore final Map<String, String> allRequestParams) {
		return this.userCrudRepository.saveAll(users);
	}

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN'})")
	@DeleteMapping(path = "/users")
	public List<User> deletes(@RequestParam(name = "id", required=false) final List<Long> ids, @RequestParam @ApiIgnore final Map<String, String> allRequestParams) {
		if ((ids == null) || (ids.isEmpty())) {
			throw new IllegalArgumentException("Atleast one 'id' parameter is required.");
		}
		final List<User> users = this.reads(ids, allRequestParams);
		this.userCrudRepository.deleteAllById(ids);
		return users;
	}

	//////////////////////////////////////////////////////////////////////////////////////////////////////////

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN','OPS_USER'})")
	@GetMapping(path = "/users/filtered")
	public List<User> filteredReads(
		@RequestParam(required=false) final String realm,
		@RequestParam(required=false) final String[] username,
		@RequestParam(required=false) final String[] emailAddress,
		@RequestParam(required=false) final String[] firstName,
		@RequestParam(required=false) final String[] lastName,
		@RequestParam @ApiIgnore final Map<String, String> allRequestParams
	) {
		final String[][] nonRealmParameters = { username, emailAddress, firstName, lastName };
		if (Arrays.stream(nonRealmParameters).filter(p -> p != null).count() > 1) {
			throw new IllegalArgumentException("Multiple search parameters not supported.");
		}
		if (realm == null) {
			if (username != null) {
				return this.userCrudRepository.findByUsernameIn(username);
			} else if (emailAddress != null) {
				return this.userCrudRepository.findByEmailAddressIn(emailAddress);
			} else if (lastName != null) {
				return this.userCrudRepository.findByLastNameIn(lastName);
			} else if (firstName != null) {
				return this.userCrudRepository.findByFirstNameIn(firstName);
			}
			return this.userCrudRepository.findAll();
		}
		if (username != null) {
			return this.userCrudRepository.findByRealmAndUsernameIn(realm, username);
		} else if (emailAddress != null) {
			return this.userCrudRepository.findByRealmAndEmailAddressIn(realm, emailAddress);
		} else if (lastName != null) {
			return this.userCrudRepository.findByRealmAndLastNameIn(realm, lastName);
		} else if (firstName != null) {
			return this.userCrudRepository.findByRealmAndFirstNameIn(realm, firstName);
		}
		return this.userCrudRepository.findByRealm(realm);
	}

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN'})")
	@DeleteMapping(path = "/users/filtered")
	public List<User> filteredDeletes(
		@RequestParam(required=true)  final String realm,
		@RequestParam(required=false) final String[] username,
		@RequestParam(required=false) final String[] emailAddress,
		@RequestParam(required=false) final String[] firstName,
		@RequestParam(required=false) final String[] lastName,
		@RequestParam @ApiIgnore final Map<String, String> allRequestParams
	) {
		if (this.wellKnownUsers.realms().contains(realm)) {
			// at least one other filter must be present to allow bulk delete in a protected realm (e.g. OPS, APP)
			final String[][] nonRealmParameters = { username, emailAddress, firstName, lastName };
			if (Arrays.stream(nonRealmParameters).filter(p -> p != null).count() == 0) {
				throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Delete by realm ['" + realm + "'] not allowed.");
			}
		}
		final List<User> users = this.filteredReads(realm, username, emailAddress, firstName, lastName, allRequestParams);
		this.userCrudRepository.deleteAll(users);
		return users;
	}
}