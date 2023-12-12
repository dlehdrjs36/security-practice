package spring.securitypractice.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public UserDetailsManager users() {
        UserDetails user = User.builder()
                .username("user")
                .password("{noop}1111")
                .roles("USER")
                .build();

        UserDetails sys = User.builder()
                .username("sys")
                .password("{noop}1111")
                .roles("SYS")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password("{noop}1111")
                .roles("ADMIN", "SYS", "USER")
                .build();

        return new InMemoryUserDetailsManager( user, sys, admin );
    }

    @Bean
    @Order(1)
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        String[] ignoreUrl = {"/loginPage", "/login"};
        HttpSecurity httpSecurity = http
//                .csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable()) //JWT를 쿠키에 저장하지 않는 경우에는 사용할 필요없음
                .headers(httpSecurityHeadersConfigurer -> httpSecurityHeadersConfigurer.frameOptions(frameOptionsConfig -> frameOptionsConfig.disable()))
                .formLogin(formLoginConfigurer -> formLoginConfigurer
//                        .loginPage("/loginPage")
                                .loginProcessingUrl("/login_proc")
                                .usernameParameter("userId")
                                .passwordParameter("passwd")
                                .defaultSuccessUrl("/", true) //로그인 성공 후 이동하는 페이지
                                .failureUrl("/login")
                                .successHandler((request, response, authentication) -> {
                                    //예외 발생 시, 여기에 이전 세션 정보가 저장되어있다
                                    RequestCache requestCache = new HttpSessionRequestCache();
                                    SavedRequest savedRequest = requestCache.getRequest(request, response);
                                    String redirectUrl = savedRequest.getRedirectUrl();
                                    response.sendRedirect(redirectUrl); //인증에 성공 후, 이동하고자 하는 곳으로 이동
//                                        System.out.println("authentication : " + authentication.getName());
//                                        response.sendRedirect("/");
                                })
//                                .failureHandler(new AuthenticationFailureHandler() {
//                                    @Override
//                                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                                        System.out.println("exception : " + exception.getMessage());
//                                        response.sendRedirect("/login");
//                                    }
//                                })
                )
                //스프링 시큐리티가 로그아웃을 처리할 때, 기본적으로 post 방식으로 처리한다. 추가설정을 통해 변경가능
                .logout(httpSecurityLogoutConfigurer -> httpSecurityLogoutConfigurer.logoutUrl("/logout"))
                .rememberMe(httpSecurityRememberMeConfigurer -> httpSecurityRememberMeConfigurer.rememberMeParameter("remember")
                        .tokenValiditySeconds(3600) //토큰 만료 시간. Default 14일
                        .alwaysRemember(true) //RememberMe 기능이 활성화 되지 않아도 항상 실행
                )
                .sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionFixation()
                        .changeSessionId()
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                );

        //인가 설정
        httpSecurity.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry
                        .requestMatchers(ignoreUrl).permitAll() //해당 경로 모두 허용처리
                        .requestMatchers("/user").hasRole("USER") // USER 권한만 허용
//                        .requestMatchers("/admin/pay").hasRole("ADMIN") // ADMIN 권한만 허용
//                        .requestMatchers("/admin/**").hasAnyRole("ADMIN", "SYS")// ADMIN, SYS 권한만 허용
                        .anyRequest()
                        .authenticated());

        //인증, 인가 예외 처리
        httpSecurity.exceptionHandling(httpSecurityExceptionHandlingConfigurer -> httpSecurityExceptionHandlingConfigurer
//                .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                        response.sendRedirect("/login"); //우리가 직접 익명클래스를 만들었기 때문에 스프링 시큐리티의 로그인 페이지가 아님
//                    }
//                })
                .accessDeniedHandler((request, response, accessDeniedException) -> response.sendRedirect("/denied"))
        );

        //자식 스레드에서도 Security Context 공유하여 사용할 수 있도록 처리
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

        return httpSecurity.build();
    }
}
