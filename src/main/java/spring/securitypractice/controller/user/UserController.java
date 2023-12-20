package spring.securitypractice.controller.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import spring.securitypractice.domain.Account;
import spring.securitypractice.domain.AccountDto;
import spring.securitypractice.service.UserService;

@Controller
public class UserController {

    private final PasswordEncoder passwordEncoder;
    private final UserService userService;

    @Autowired
    public UserController(PasswordEncoder passwordEncoder, UserService userService) {
        this.passwordEncoder = passwordEncoder;
        this.userService = userService;
    }

    @GetMapping("/mypage")
    public String config() {
        return "user/mypage";
    }

    @GetMapping("/users")
    public String users() {
        return "user/login/register";
    }

    @PostMapping("/users")
    public String createUser(AccountDto accountDto) {
        Account account = Account.convert(accountDto, passwordEncoder);
        userService.createUser(account);

        return "redirect:/";
    }

}