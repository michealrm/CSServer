package com.cheatscan.server.socket;

import java.net.Socket;

public class Handshake {

	private HandshakeProtocol protocol;
	
	public Handshake(Socket socket) {
		protocol = new HandshakeProtocol(socket);
	}
	
	public HandshakeProtocol getProtocol() {
		return protocol;
	}
	
}
