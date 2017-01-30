package com.cheatscan.server.log;

import java.net.Socket;
import java.util.ArrayList;

import com.cheatscan.server.Server;
import com.cheatscan.server.User;
import com.cheatscan.server.ViolationType;

public class Logger {
	
	ArrayList<String> log;
	
	public Logger() {
		log = new ArrayList<String>();
	}
	
	public void log(String msg) {
		String message = msg;
		log.add(message);
		System.out.println(message);
	}
	
	public void socketLog(int socket, String msg) {
		log("[" + socket + "] " + msg);
	}
	
	public void scanLog(int socket, User user, String msg) {
		socketLog(socket, user.getIndex() + " > " + msg);
	}
	
	public void exceptionLog(String msg, Exception e) {
		log("[ERROR] " + msg + " -> " + e.getMessage());
	}
	
	public void violationLog(Socket socket, User user, ViolationType type, double risk, String adminMsg) {
		socketLog(Server.getSocketIndex(socket)+1, user.getUUID() + " flagged violation " + type + " (" + risk + ") --> " + adminMsg);
	}
	
}
