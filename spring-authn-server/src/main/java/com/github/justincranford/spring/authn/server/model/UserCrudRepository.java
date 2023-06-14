package com.github.justincranford.spring.authn.server.model;

import java.util.List;

import org.springframework.data.repository.ListCrudRepository;

import com.github.justincranford.spring.util.model.User;

public interface UserCrudRepository extends ListCrudRepository<User, Long> {
    List<User> findByUsernameIn(String[] usernames);
    List<User> findByEmailAddressIn(String[] emailAddresses);
    List<User> findByFirstNameIn(String[] firstNames);
    List<User> findByLastNameIn(String[] lastNames);

    List<User> findByUsername(String username);
    List<User> findByEmailAddress(String emailAddress);
    List<User> findByFirstName(String firstName);
    List<User> findByLastName(String lastName);

    List<User> findAll();

    List<User> findByRealmAndUsernameIn(String realm, String[] usernames);
    List<User> findByRealmAndEmailAddressIn(String realm, String[] emailAddresses);
    List<User> findByRealmAndFirstNameIn(String realm, String[] firstNames);
    List<User> findByRealmAndLastNameIn(String realm, String[] lastNames);

    List<User> findByRealmAndUsername(String realm, String username);
    List<User> findByRealmAndEmailAddress(String realm, String emailAddress);
    List<User> findByRealmAndFirstName(String realm, String firstName);
    List<User> findByRealmAndLastName(String realm, String lastName);

    List<User> findByRealm(String realm);
}