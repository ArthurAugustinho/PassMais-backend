package br.com.passmais.authservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import br.com.passmais.authservice.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
}
