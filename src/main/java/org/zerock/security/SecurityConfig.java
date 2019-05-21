package org.zerock.security;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.extern.java.Log;

@Log
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private DataSource dataSource;
	
	@Autowired
	private ZerockUsersService zerockUsersService;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		log.info("security config.................");
		
		http.authorizeRequests().antMatchers("/guest/**").permitAll();
		
		http.authorizeRequests().antMatchers("/manager/**").hasRole("MANAGER");
		
		http.authorizeRequests().antMatchers("/admin/**").hasRole("ADMIN");
		
		http.formLogin().loginPage("/login");
		
		http.exceptionHandling().accessDeniedPage("/accessDenied");
		
		http.logout().logoutUrl("/logout").invalidateHttpSession(true);
		
		http.userDetailsService(zerockUsersService);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		log.info("build Auth global........");
		
//		auth.inMemoryAuthentication()
//		.withUser("manager")
//		.password("{noop}1111")
//		.roles("MANAGER");
		
//		String query1 = "SELECT uid username, upw password, true enabled FROM tbl_members WHERE uid = ?";
//		
//		String query2 = "SELECT member uid, role_name role FROM tbl_member_roles WHERE member = ?";
//		
//		auth.jdbcAuthentication()
//		.dataSource(dataSource)
//		.usersByUsernameQuery(query1)
//		.rolePrefix("ROLE_")
//		.authoritiesByUsernameQuery(query2);
		
		auth.userDetailsService(zerockUsersService).passwordEncoder(passwordEncoder());
	}
	
}
