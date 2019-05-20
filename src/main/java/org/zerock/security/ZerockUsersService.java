package org.zerock.security;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.zerock.domain.Member;
import org.zerock.persistence.MemberRepository;

import lombok.extern.java.Log;

@Service
@Log
public class ZerockUsersService implements UserDetailsService {

	@Autowired
	private MemberRepository repo;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//		User sampleUser = new User(username, "{noop}1111", Arrays.asList(new SimpleGrantedAuthority("ROLE_MANAGER")));
		Optional<Member> result = repo.findById(username);
		if (result.isPresent()) {
			Member m = result.get();
			log.info("user: " + m.getUid() + " / passwd: " + m.getUpw());
			ZerockSecurityUser user = new ZerockSecurityUser(m);
			return user;
		}
		
		return null;
	}

}
