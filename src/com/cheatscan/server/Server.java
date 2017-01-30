package com.cheatscan.server;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.SQLException;
import java.util.ArrayList;

import org.apache.commons.configuration2.Configuration;
import org.apache.commons.configuration2.builder.fluent.Configurations;
import org.apache.commons.configuration2.ex.ConfigurationException;

import com.cheatscan.server.handlers.CLIHander;
import com.cheatscan.server.handlers.SQLHander;
import com.cheatscan.server.handlers.ViolationHandler;
import com.cheatscan.server.log.Logger;
import com.cheatscan.server.socket.ConnectionPool;
import com.maxmind.db.CHMCache;
import com.maxmind.geoip2.DatabaseReader;

public class Server {
	
	public static Logger logger;
	
	public static final int PORT;
	public static final int TIMEOUT_SECONDS;
	
	static {
		logger = new Logger();
		configs = new Configurations();
		logger.log("Checking config file for constants");
		try {
			Configuration config = Server.configs.properties(new File("properties/config.properties"));
			TIMEOUT_SECONDS = config.getInt("client_timeout_seconds");
			logger.log("TIMEOUT_SECONDS = " + TIMEOUT_SECONDS);
			PORT = config.getInt("port");
			logger.log("PORT = " + PORT);
		} catch (ConfigurationException e) {
			logger.log("Invalid config file");
			throw new RuntimeException("Could not initiate server.", e);
		}
	}

	public static boolean active = true;
	public static ConnectionPool pool;
	public static ArrayList<Socket> sockets;
	public static ServerSocket welcome = null;
	public static Configurations configs;
	public static SQLHander sql;
	public static File detections;
	public static DatabaseReader geoIPDB;
	public static ViolationHandler vHandler;
	
	public static void main(String[] args) throws IOException {
		
		// Required files
		
	   	 detections = new File("textdetections.yaml");
	   	 if(!detections.exists()) {
	   		 logger.log("Could not find textdetections.yaml");
	   		 System.exit(-1);
	   	 }
	   	 File db = new File("GeoLite2-City.mmdb");
	   	 if(!db.exists()) {
	   		 logger.log("Could not find GeoLite2-City.mmdb");
	   		 System.exit(-1);
	   	 }
	   	 geoIPDB = new DatabaseReader.Builder(db).withCache(new CHMCache()).build();
	   	 
	   	// Required files
		
	   	vHandler = new ViolationHandler();
		try {
			logger.log("Initiating server socket on port " + PORT);
			welcome = new ServerSocket(PORT);
        } catch (IOException e) {
            logger.log("Could not listen on port " + PORT);
            System.exit(-1);
        }
		logger.log("Initiating socket pool");
		pool = new ConnectionPool();
		sockets = new ArrayList<Socket>();
		logger.log("Initiating CLI Handler");
		new CLIHander().start();
		try {
			sql = new SQLHander();
		} catch (ConfigurationException e) {
			logger.exceptionLog("Could not connect to the SQL server", e);
			System.exit(-1);
		} catch (ClassNotFoundException e) {
			Server.logger.exceptionLog("Could not find JDBC Driver", e);
			System.exit(-1);
		} catch (SQLException e) {
			Server.logger.exceptionLog("Could not connect to SQL server", e);
			System.exit(-1);
		}
		
		logger.log("Adding shutdown hook");
		Runtime.getRuntime().addShutdownHook(new Thread() {
			public void run() {
				if(active)
					CLIHander.stopServer();
			}
		});
		
		/// Client handler ///
		logger.log("Initiating client handler loop");
		while(active) {
			Socket client = welcome.accept();
			client.setSoTimeout(TIMEOUT_SECONDS * 1000);
			sockets.add(client);
			logger.socketLog(sockets.size(), "Accepted connection from " + client.getRemoteSocketAddress());
			pool.newConnection(client);
		}
		
		welcome.close();
	}
	
	public static int getSocketIndex(Socket socket) {
		for(int i = 0;i<sockets.size();i++)
			if(sockets.get(i) == socket)
				return i;
		return -1;
	}
	
}
