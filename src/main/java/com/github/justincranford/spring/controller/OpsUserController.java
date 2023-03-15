package com.github.justincranford.spring.controller;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.security.Principal;
import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
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

import com.github.justincranford.spring.model.user.OpsUser;
import com.github.justincranford.spring.model.user.OpsUserCrudRepository;
import com.github.justincranford.spring.model.user.OpsUserNotFoundException;

@CrossOrigin(origins={"https://localhost:8443"})
@RestController
@RequestMapping(path="/api/ops", produces={APPLICATION_JSON_VALUE})
public class OpsUserController {
	@Autowired
	private OpsUserCrudRepository opsUserRepository;

	// TODO @PatchMapping

	//////////////////////////////////////////////////////////////////////////////////////////////////////////

	@PostMapping(path = "/user", consumes = { APPLICATION_JSON_VALUE })
	@ResponseStatus(HttpStatus.CREATED)
	public OpsUser create(final Principal principal, @RequestBody final OpsUser user) {
		return this.opsUserRepository.save(user);
	}

	@GetMapping(path = "/user/{id}")
	public OpsUser read(final Principal principal, @PathVariable final Long id) {
		return this.opsUserRepository.findById(id).orElseThrow(OpsUserNotFoundException::new);
	}

	@PutMapping(path = "/user", consumes = { APPLICATION_JSON_VALUE })
	public OpsUser update(final Principal principal, @RequestBody final OpsUser user) {
		this.opsUserRepository.findById(user.getId()).orElseThrow(OpsUserNotFoundException::new);
		return this.opsUserRepository.save(user);
	}

	@DeleteMapping(path = "/user/{id}")
	public OpsUser delete(final Principal principal, @PathVariable final Long id) {
		final OpsUser user = this.opsUserRepository.findById(id).orElseThrow(OpsUserNotFoundException::new);
		this.opsUserRepository.deleteById(id);
		return user;
	}

	//////////////////////////////////////////////////////////////////////////////////////////////////////////

	@PostMapping(path = "/users", consumes = { APPLICATION_JSON_VALUE })
//	@ResponseStatus(HttpStatus.CREATED)
	public List<OpsUser> creates(final Principal principal, @RequestBody final Iterable<OpsUser> users) {
		return this.opsUserRepository.saveAll(users);
	}

	@GetMapping(path = "/users")
	public List<OpsUser> reads(final Principal principal, @RequestParam(name = "id", required = false) final List<Long> ids) {
		if (ids == null) {
			return this.opsUserRepository.findAll();
		}
		return this.opsUserRepository.findAllById(ids);
	}

	@PutMapping(path = "/users", consumes = { APPLICATION_JSON_VALUE })
	public List<OpsUser> updates(final Principal principal, @RequestBody final Iterable<OpsUser> users) {
		return this.opsUserRepository.saveAll(users);
	}

	@DeleteMapping(path = "/users")
	public List<OpsUser> deletes(final Principal principal, @RequestParam(name = "id", required = false) final List<Long> ids) {
		final List<OpsUser> users = this.opsUserRepository.findAllById(ids);
		if (ids == null) {
			this.opsUserRepository.deleteAllById(ids);
		}
		return users;
	}

	//////////////////////////////////////////////////////////////////////////////////////////////////////////

	@GetMapping(path = "/users/search")
	public List<OpsUser> filteredReads(final Principal principal, @RequestParam(required = false) final String emailAddress, @RequestParam(required = false) final String firstName, @RequestParam(required = false) final String lastName) {
		final List<OpsUser> users;
		if ((emailAddress != null) && (firstName != null) && (lastName != null)) {
			users = this.opsUserRepository.findByEmailAddressAndFirstNameAndLastName(emailAddress, firstName, lastName);
		} else if ((emailAddress != null) && (firstName != null)) {
			users = this.opsUserRepository.findByEmailAddressAndFirstName(emailAddress, firstName);
		} else if ((emailAddress != null) && (lastName != null)) {
			users = this.opsUserRepository.findByEmailAddressAndLastName(emailAddress, lastName);
		} else if ((firstName != null) && (lastName != null)) {
			users = this.opsUserRepository.findByFirstNameAndLastName(firstName, lastName);
		} else if (emailAddress != null) {
			users = this.opsUserRepository.findByEmailAddress(emailAddress);
		} else if (firstName != null) {
			users = this.opsUserRepository.findByFirstName(firstName);
		} else if (lastName != null) {
			users = this.opsUserRepository.findByLastName(lastName);
		} else {
			users = Collections.emptyList();
		}
		return users;
	}

	@DeleteMapping(path = "/users/search")
	public List<OpsUser> filteredDeletes(final Principal principal, @RequestParam(required = false) final String emailAddress, @RequestParam(required = false) final String firstName, @RequestParam(required = false) final String lastName) {
		final List<OpsUser> users = this.filteredReads(principal, emailAddress, firstName, lastName);
		this.opsUserRepository.deleteAll(users);
		return users;
	}
}