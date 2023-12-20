package spring.securitypractice.security.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import spring.securitypractice.repository.UserRepository;
import spring.securitypractice.security.common.FormAuthenticationDetailsSource;
import spring.securitypractice.security.handler.CustomAccessDeniedHandler;
import spring.securitypractice.security.handler.CustomAuthenticationFailureHandler;
import spring.securitypractice.security.handler.CustomAuthenticationHandler;
import spring.securitypractice.security.provider.CustomAuthenticationProvider;
import spring.securitypractice.security.service.CustomUserDetailsService;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * 정적 파일은 보안 필터를 거치지 않고 통과 처리. 정적 자원들이 보안 필터에 걸려 차단되면 이미지 등이 정상 동작 하지 않을 수 있다.
     * @return
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository) {
        return new CustomUserDetailsService(userRepository);
    }

    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService) {
        return new CustomAuthenticationProvider(userDetailsService, passwordEncoder());
    }

    @Bean
    public AuthenticationDetailsSource customAuthenticationDetailsSource() {
        return new FormAuthenticationDetailsSource();
    }

    @Bean
    public AuthenticationSuccessHandler customAuthenticationSuccessHandler() {
        return new CustomAuthenticationHandler();
    }

    @Bean
    public AuthenticationFailureHandler customAuthenticationFailureHandler() {
        return new CustomAuthenticationFailureHandler();
    }

    @Bean
    public AccessDeniedHandler customAccessDeniedHandler() {
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }

    /**
     * 보안 필터를 거침
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(1)
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //인가 설정
        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/users", "/login*").permitAll() // login* : customAuthenticationFailureHandler의 경로 허용을 위한 처리
                        .requestMatchers("/mypage").hasRole("USER")
                        .requestMatchers("/messages").hasRole("MANAGER")
                        .requestMatchers("/config").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .exceptionHandling(httpSecurityExceptionHandlingConfigurer -> httpSecurityExceptionHandlingConfigurer.accessDeniedHandler(customAccessDeniedHandler())) //접근거부시 사용되는 핸들러 등록
                .formLogin(formLoginConfigurer -> formLoginConfigurer
                        .loginPage("/login")
                        .loginProcessingUrl("/login_proc")
                        .defaultSuccessUrl("/")
                        .failureUrl("/login")
                        .authenticationDetailsSource(customAuthenticationDetailsSource()) // 인증 객체에 사용자 추가 요청 정보를 저장
                        .successHandler(customAuthenticationSuccessHandler()) //인증에 성공한 이후에 호출되어 동작
                        .failureHandler(customAuthenticationFailureHandler()) //인증에 실패한 경우 호출되어 동작
                        .permitAll()
                );


        return http.build();
    }
}
