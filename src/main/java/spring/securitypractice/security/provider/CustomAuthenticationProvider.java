package spring.securitypractice.security.provider;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import spring.securitypractice.domain.Account;
import spring.securitypractice.security.common.FormWebAuthenticationDetails;
import spring.securitypractice.security.service.AccountContext;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public CustomAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * 토큰 타입이 일치할 때, 검증을 위한 구현
     * @param authentication
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String name = authentication.getName(); //유저 네임
        String password = (String)authentication.getCredentials();//패스워드
        FormWebAuthenticationDetails formWebAuthenticationDetails = (FormWebAuthenticationDetails) authentication.getDetails();

        if(!"secret".equals(formWebAuthenticationDetails.getSecretKey())) {
            throw new InsufficientAuthenticationException("InsufficientAuthenticationException");
        }

        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(name);
        Account account = accountContext.getAccount();
        if(!passwordEncoder.matches(password, account.getPassword())) {
            throw new BadCredentialsException("BadCredentialsException");
        }

        //인증 성공 처리된 토큰을 생성하여 전달
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
        return authenticationToken;
    }

    /**
     * 토큰 타입이 일치하는지 확인
     * @param authentication
     * @return
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
