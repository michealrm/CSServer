package com.cheatscan.server;

import java.security.SecureRandom;

public class User {

	public static final int SECRET_LENGTH = 32;
	
	private final String secret;
	private String uuid;
	private int index;
	
	public User(String uuid) {
		
		this.uuid = uuid;
		
		String secret = "";
		SecureRandom random = new SecureRandom();
		for(int i = 0;i<SECRET_LENGTH;i++)
			secret += (char)(random.nextInt(126 - 48 + 1) + 48);
		this.secret = secret;
		
		index = 0;
		
	}
	
	public User(String uuid, String secret) {
		this.uuid = uuid;
		this.secret = secret;
		index = 0;
	}
	
	public User() {
		this(null);
	}
	
	/**
	 * @return String used for client verification
	 */
	public String getSecret() {
		return secret;
	}
	
	public String getUUID() {
		return uuid;
	}
	
	public int getIndex() {
		return index;
	}
	
	public void setIndex(int index) {
		this.index = index;
	}
	
}
