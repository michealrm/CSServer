package com.cheatscan.server.socket;

public interface SocketInputEvent {
	
	public void onInput(String input, HandshakeProtocol hs);
	
}
