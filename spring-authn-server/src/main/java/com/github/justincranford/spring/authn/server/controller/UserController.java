package com.github.justincranford.spring.authn.server.controller;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.security.Principal;
import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.github.justincranford.spring.authn.server.model.SimpleGrantedAuthorityNames;
import com.github.justincranford.spring.authn.server.model.UserCrudRepository;
import com.github.justincranford.spring.authn.server.model.UserNotFoundException;
import com.github.justincranford.spring.util.model.User;

@CrossOrigin(origins={"https://127.0.0.1:8443"})
@RestController
@RequestMapping(path="/api", produces={APPLICATION_JSON_VALUE})
public class UserController {
	@Autowired
	private UserCrudRepository userCrudRepository;

	// TODO @PatchMapping

	//////////////////////////////////////////////////////////////////////////////////////////////////////////

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN'})")
	@PostMapping(path = "/user", consumes = { APPLICATION_JSON_VALUE })
	@ResponseStatus(HttpStatus.CREATED)
	public User create(final Principal principal, @RequestBody final User user) {
		return this.userCrudRepository.save(user);
	}

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN','OPS_USER'})")
	@GetMapping(path = "/user/{id}")
	public User read(final Principal principal, @PathVariable final Long id) {
		return this.userCrudRepository.findById(id).orElseThrow(UserNotFoundException::new);
	}

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN'})")
	@PutMapping(path = "/user", consumes = { APPLICATION_JSON_VALUE })
	public User update(final Principal principal, @RequestBody final User user) {
		this.userCrudRepository.findById(user.getId()).orElseThrow(UserNotFoundException::new);
		return this.userCrudRepository.save(user);
	}

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN'})")
	@DeleteMapping(path = "/user/{id}")
	public User delete(final Principal principal, @PathVariable final Long id) {
		final User user = this.userCrudRepository.findById(id).orElseThrow(UserNotFoundException::new);
		this.userCrudRepository.deleteById(id);
		return user;
	}

	//////////////////////////////////////////////////////////////////////////////////////////////////////////

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN'})")
	@PostMapping(path = "/users", consumes = { APPLICATION_JSON_VALUE })
//	@ResponseStatus(HttpStatus.CREATED)
	public List<User> creates(final Principal principal, @RequestBody final Iterable<User> users) {
		return this.userCrudRepository.saveAll(users);
	}

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN','OPS_USER'})")
	@GetMapping(path = "/users")
	public List<User> reads(final Principal principal, @RequestParam(name = "id", required = false) final List<Long> ids) {
		if (ids == null) {
			return this.userCrudRepository.findAll();
		}
		return this.userCrudRepository.findAllById(ids);
	}

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN'})")
	@PutMapping(path = "/users", consumes = { APPLICATION_JSON_VALUE })
	public List<User> updates(final Principal principal, @RequestBody final Iterable<User> users) {
		return this.userCrudRepository.saveAll(users);
	}

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN'})")
	@DeleteMapping(path = "/users")
	public List<User> deletes(final Principal principal, @RequestParam(name = "id", required = false) final List<Long> ids) {
		final List<User> users = this.userCrudRepository.findAllById(ids);
		if (ids == null) {
			this.userCrudRepository.deleteAllById(ids);
		}
		return users;
	}

	//////////////////////////////////////////////////////////////////////////////////////////////////////////

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN','OPS_USER'})")
	@GetMapping(path = "/filtered/users")
	public List<User> filteredReads(final Principal principal, @RequestParam(required = true) final String realm, @RequestParam(required = false) final String emailAddress, @RequestParam(required = false) final String firstName, @RequestParam(required = false) final String lastName) {
		if ((emailAddress != null) && (firstName != null) && (lastName != null)) {
			return this.userCrudRepository.findByRealmAndEmailAddressAndFirstNameAndLastName(realm, emailAddress, firstName, lastName);
		} else if ((emailAddress != null) && (firstName != null)) {
			return this.userCrudRepository.findByRealmAndEmailAddressAndFirstName(realm, emailAddress, firstName);
		} else if ((emailAddress != null) && (lastName != null)) {
			return this.userCrudRepository.findByRealmAndEmailAddressAndLastName(realm, emailAddress, lastName);
		} else if ((firstName != null) && (lastName != null)) {
			return this.userCrudRepository.findByRealmAndFirstNameAndLastName(realm, firstName, lastName);
		} else if (emailAddress != null) {
			return this.userCrudRepository.findByRealmAndEmailAddress(realm, emailAddress);
		} else if (firstName != null) {
			return this.userCrudRepository.findByRealmAndFirstName(realm, firstName);
		} else if (lastName != null) {
			return this.userCrudRepository.findByRealmAndLastName(realm, lastName);
		}
		return Collections.emptyList();
	}

	@PreAuthorize("hasAnyRole({'OPS_ADMIN','APP_ADMIN'})")
	@DeleteMapping(path = "/filtered/users")
	public List<User> filteredDeletes(final Principal principal, @RequestParam(required = false) final String realm, @RequestParam(required = false) final String emailAddress, @RequestParam(required = false) final String firstName, @RequestParam(required = false) final String lastName) {
		final List<User> users = this.filteredReads(principal, realm, emailAddress, firstName, lastName);
		this.userCrudRepository.deleteAll(users);
		return users;
	}
}