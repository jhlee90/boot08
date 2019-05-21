package org.zerock.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.zerock.domain.Member;
import org.zerock.persistence.MemberRepository;

import lombok.extern.java.Log;

@Controller
@RequestMapping("/member/")
@Log
public class MemberController {

	@Autowired
	private PasswordEncoder pwEncoder;
	
	@Autowired
	private MemberRepository repo;
	
	@GetMapping("/join")
	public void join() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		log.info("principal: " + auth.getPrincipal());
	}
	
	@PostMapping("/join")
	public String joinPost(@ModelAttribute("member") Member member) {
		log.info("MEMBER: " + member);
		
		String encryptPw = pwEncoder.encode(member.getUpw());
		log.info("en: " + encryptPw);
		member.setUpw(encryptPw);
		repo.save(member);
		
		return "/member/joinResult";
	}
}
