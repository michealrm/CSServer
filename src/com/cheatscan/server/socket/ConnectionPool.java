package com.cheatscan.server.socket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import com.cheatscan.server.Server;

public class ConnectionPool {

	public static final int POOL_LENGTH = 100;
	
	private ExecutorService executor;
	
	public ConnectionPool() {
        executor = Executors.newFixedThreadPool(POOL_LENGTH);
//        while (!executor.isTerminated()) {}

	}
	
	public int getActiveCount() {
		return ((ThreadPoolExecutor)executor).getActiveCount();
	}
	
	public void newConnection(Socket socket) {
		executor.execute(new Handshake(socket).getProtocol());
	}
	
	public void shutdown() {
		Server.logger.log("Shutting down thread pool.");
		executor.shutdown();
	}
	
}
