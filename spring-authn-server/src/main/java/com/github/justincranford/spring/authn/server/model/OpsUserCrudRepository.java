package com.github.justincranford.spring.authn.server.model;

import java.util.List;

import org.springframework.data.repository.ListCrudRepository;

public interface OpsUserCrudRepository extends ListCrudRepository<OpsUser, Long> {
    List<OpsUser> findByUsername(String username);
    List<OpsUser> findByEmailAddress(String emailAddress);
    List<OpsUser> findByFirstName(String firstName);
    List<OpsUser> findByMiddleName(String middleName);
    List<OpsUser> findByLastName(String lastName);
    List<OpsUser> findByIsAccountNonExpired(boolean isAccountNonExpired);
    List<OpsUser> findByIsAccountNonLocked(boolean isAccountNonLocked);
    List<OpsUser> findByIsCredentialsNonExpired(boolean isCredentialsNonExpired);
    List<OpsUser> findByIsEnabled(boolean isEnabled);

    // TODO Remove or enhance combination finds?

    List<OpsUser> findByEmailAddressAndFirstName(String emailAddress, String firstName);
    List<OpsUser> findByFirstNameAndLastName(String firstName, String lastName);
    List<OpsUser> findByEmailAddressAndLastName(String emailAddress, String lastName);

    List<OpsUser> findByEmailAddressAndFirstNameAndLastName(String emailAddress, String firstName, String lastName);
}