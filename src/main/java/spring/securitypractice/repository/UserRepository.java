package spring.securitypractice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import spring.securitypractice.domain.Account;

@Repository
public interface UserRepository extends JpaRepository<Account, Long> {

    Account findByUsername(String username);

}
