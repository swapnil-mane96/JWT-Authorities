package com.photoapp.jwtauthorities;


import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
/*
 * This class is used to parse jwt (json web token)
 */
public class JwtParserClaims {

	Jwt<?,?> jwtObject;
	
	public JwtParserClaims(String jwtString, String secretToken) {
		jwtObject = parseJwt(jwtString, secretToken);
	}
	
	/*
	 * method is used to convert jwt string to jwt java object
	 */
	Jwt<?, ?> parseJwt(String jwtString, String secretToken){
		byte[] secretKeyBytes = Base64.getEncoder().encode(secretToken.getBytes());
		//SecretKey secretKey = Keys.hmacShaKeyFor(secretKeyBytes);
		SecretKey secretKey = new SecretKeySpec(secretKeyBytes, SignatureAlgorithm.HS512.getJcaName());
		
		JwtParser jwtParser = Jwts.parser()
		.verifyWith(secretKey)
		.build();

		return jwtParser.parse(jwtString); //this line is parsing string into validated Java object.
	}
	
	/*
	 * this method is used to extract Roles and Authorities from jwt
	 */
	public Collection<? extends GrantedAuthority> getUserAuthorities(){
		Collection<Map<String, String>> scopes = ((Claims)this.jwtObject.getPayload()).get("scope", List.class);
		
		return scopes.stream()
				.map((scopeMap) -> new SimpleGrantedAuthority(scopeMap.get("authority")))
				.collect(Collectors.toList());
	}
	
	/*
	 * reading jwt subject(userId)
	 * I'm calling this method get subject because user ID or username is usually stored in JWT in a claim
	   that is called subject or sub for short, and it usually contains identifier of a user
	 */
	public String getJwtSubject() {
		return ((Claims)this.jwtObject.getPayload()).getSubject();
	}
	
	
	
	
}
