package com.github.justincranford.spring.authn.server.model;

import java.util.List;

import org.springframework.data.repository.ListCrudRepository;

import com.github.justincranford.spring.util.model.User;

public interface UserCrudRepository extends ListCrudRepository<User, Long> {
    List<User> findByUsername(String username);
    List<User> findByRealmAndUsername(String realm, String username);
    List<User> findByRealmAndEmailAddress(String realm, String emailAddress);
    List<User> findByRealmAndFirstName(String realm, String firstName);
    List<User> findByRealmAndMiddleName(String realm, String middleName);
    List<User> findByRealmAndLastName(String realm, String lastName);
    List<User> findByRealmAndIsAccountNonExpired(String realm, boolean isAccountNonExpired);
    List<User> findByRealmAndIsAccountNonLocked(String realm, boolean isAccountNonLocked);
    List<User> findByRealmAndIsCredentialsNonExpired(String realm, boolean isCredentialsNonExpired);
    List<User> findByRealmAndIsEnabled(String realm, boolean isEnabled);

    // TODO Remove or enhance combination finds?

    List<User> findByRealmAndEmailAddressAndFirstName(String realm, String emailAddress, String firstName);
    List<User> findByRealmAndFirstNameAndLastName(String realm, String firstName, String lastName);
    List<User> findByRealmAndEmailAddressAndLastName(String realm, String emailAddress, String lastName);

    List<User> findByRealmAndEmailAddressAndFirstNameAndLastName(String realm, String emailAddress, String firstName, String lastName);
}