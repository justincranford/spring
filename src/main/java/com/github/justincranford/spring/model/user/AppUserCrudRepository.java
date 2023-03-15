package com.github.justincranford.spring.model.user;

import java.util.List;

import org.springframework.data.repository.ListCrudRepository;

public interface AppUserCrudRepository extends ListCrudRepository<AppUser, Long> {
    List<AppUser> findByUsername(String username);
    List<AppUser> findByEmailAddress(String emailAddress);
    List<AppUser> findByFirstName(String firstName);
    List<AppUser> findByMiddleName(String middleName);
    List<AppUser> findByLastName(String lastName);
    List<AppUser> findByIsAccountNonExpired(boolean isAccountNonExpired);
    List<AppUser> findByIsAccountNonLocked(boolean isAccountNonLocked);
    List<AppUser> findByIsCredentialsNonExpired(boolean isCredentialsNonExpired);
    List<AppUser> findByIsEnabled(boolean isEnabled);

    // TODO Remove or enhance combination finds?

    List<AppUser> findByEmailAddressAndFirstName(String emailAddress, String firstName);
    List<AppUser> findByFirstNameAndLastName(String firstName, String lastName);
    List<AppUser> findByEmailAddressAndLastName(String emailAddress, String lastName);

    List<AppUser> findByEmailAddressAndFirstNameAndLastName(String emailAddress, String firstName, String lastName);
}