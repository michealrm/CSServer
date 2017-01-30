package com.cheatscan.server.handlers;

import java.io.IOException;
import java.net.Socket;
import java.sql.SQLException;
import java.util.Scanner;

import com.cheatscan.server.Server;

public class CLIHander extends Thread {
	
	private Scanner scanner;
	
	public void run() {
		scanner = new Scanner(System.in);
		waitForInput();
	}
	
	private void waitForInput() {
		String line = scanner.nextLine();
		
		boolean loop = true;
		switch (line) {
		case "stop":
		case "exit":
			stopServer();
			loop = false;
			break;
		case "active":
		case "threads":
		case "count":
			int count = Server.pool.getActiveCount();
			Server.logger.log("There " + (count != 1 ? "are " : "is ") + count + " active thread" + (Server.pool.getActiveCount() != 1 ? "s" : "") + " in the pool");
			break;
		default:
			Server.logger.log("\"" + line + "\" is not a command");
		}
		if(loop)
			waitForInput();
	}


	public static void stopServer() {
		Server.logger.log("Stopping server!");
		Server.active = false;
		int activeSockets = 0;
		for(Socket socket : Server.sockets)
			if(!socket.isClosed())
				activeSockets++;
		if(activeSockets > 0)
			Server.logger.log("Waiting for " + activeSockets + " sockets.");
		
		while(activeSockets > 0) {
			int newActiveSockets = 0;
			for(Socket socket : Server.sockets)
				if(!socket.isClosed())
					newActiveSockets++;
			if(newActiveSockets != activeSockets) {
				activeSockets = newActiveSockets;
				Server.logger.log("Waiting for " + activeSockets + " sockets.");
			}
		}
		
		try {
			Server.sql.stop();
		} catch (SQLException e1) {
			Server.logger.exceptionLog("Couldn't close SQL connection", e1);
		}

		// Close here
		
		if(Server.welcome != null && !Server.welcome.isClosed()) {
			try {
				Server.welcome.close();
			} catch (IOException e) {
				Server.logger.log("Could not close server socket. " + e.getMessage());
			}
		}
		
		System.exit(0);
		
	}
	
}
