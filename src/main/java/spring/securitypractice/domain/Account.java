package spring.securitypractice.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Data;
import org.springframework.security.crypto.password.PasswordEncoder;

@Entity
@Data
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;
    private String email;
    private String age;
    private String role;


    /**
     * request를 받아서 엔티티로 변환
     * @param accountDto
     * @return
     */
    public static Account convert(AccountDto accountDto, PasswordEncoder passwordEncoder) {
        Account account = new Account();
        account.setUsername(accountDto.getUsername());
        account.setPassword(passwordEncoder.encode(accountDto.getPassword()));
        account.setEmail(accountDto.getEmail());
        account.setAge(accountDto.getAge());
        account.setRole(accountDto.getRole());

        return account;
    }


}
