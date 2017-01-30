package com.cheatscan.server;

public enum ViolationType {
	
	// 10000 VLs = 100% cheating
	
	// SUSPICIOUS
	SUSPICIOUS_TIME(0000, 1000, Constants.MAX_PRIORITY),
	SUSPICIOUS_HEURISTIC(0001, 10000, Constants.MAX_PRIORITY),
	SUSPICIOUS_UNEXPECTEDINPUT(0002, 10000, Constants.MAX_PRIORITY),
	
	// ILLEGAL
	ILLEGAL_DOS(1000, 10000, Constants.MAX_PRIORITY),
	ILLEGAL_DOX(1001, 10000, Constants.MAX_PRIORITY),
	
	// CHEATS
	CHEAT_HEURISTIC(2000, 10000, 0),
	CHEAT_CHECKSUM(2001, 10000, Constants.MAX_PRIORITY),
	CHEAT_INJECT(2003, 10000, 1), // Java agents, DLLs, etc
	CHEAT_VERSIONS(2004, 10000, 1),
	CHEAT_AUTOCLICKER(2005, 10000, 1),
	CHEAT_STRINGS(2007, 10000, 1),
	// Specific clients
	CHEAT_CLIENT_VAPE(2500, 10000, 2),
	CHEAT_CLIENT_HARAMBE(2501,10000, 2),
	CHEAT_CLIENT_SPOOK(2502, 10000, 2),
	// Specific mods
	CHEAT_MOD_RADAR(2600, 10000, 2),
	CHEAT_MOD_XRAY(2601, 10000, 2),
	// Specific autoclickers
	CHEAT_AUTOCLICKER_VENECLICKER(2700, 10000, 2),
	CHEAT_AUTOCLICKER_7CLICKER(2701, 10000, 2),
	CHEAT_AUTOCLICKER_JCLICKER(2702, 10000, 2),
	CHEAT_AUTOCLICKER_ARIS(2703, 10000, 2), // com.aristhena.emily
	CHEAT_AUTOCLICKER_SYNAPSE(2704, 10000, 2);
	
	private static class Constants {
		public static final int MAX_PRIORITY = Integer.MAX_VALUE;
	}
	
	private int priority = 0;
	private int id;
	private int maxVL;
	
	private ViolationType(int id) {
		this.id = id;
	}
	
	private ViolationType(int id, int maxVL, int priority) {
		this.priority = priority;
		this.id = id;
		this.maxVL = maxVL;
	}
	
	public int getPriority() {
		return priority;
	}
	
	public int getID() {
		return id;
	}
	
	public int getMaxVL() {
		return maxVL;
	}
}