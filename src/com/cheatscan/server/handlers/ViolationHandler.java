package com.cheatscan.server.handlers;

import java.net.Socket;

import com.cheatscan.server.Server;
import com.cheatscan.server.User;
import com.cheatscan.server.ViolationType;

public class ViolationHandler {
	
	public ViolationHandler() {
		
	}
	
	public void onViolation(ViolationType type, String adminMsg, String friendlyMsg, double p, double m, User user, Socket socket) {
		double risk = p * m;
		Server.logger.violationLog(socket, user, type, risk, adminMsg);
		// risk adds onto their current risk on a detection e.g. .1 + .1
	}
	
	public void onUnexpectedInput(ViolationType type, String input, User user, Socket socket) {
		onViolation(ViolationType.SUSPICIOUS_UNEXPECTEDINPUT, "Failed check " + String.format("%04d", type.getID()) + " becuase incorrect input: " + input, "Couldn't retrive data for check", 1.0, 0.1, user, socket);
	}
	
}