package com.cheatscan.server.handlers;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;

import org.apache.commons.configuration2.Configuration;
import org.apache.commons.configuration2.ex.ConfigurationException;

import com.cheatscan.server.Server;
import com.cheatscan.server.User;

public class SQLHander {

	private Connection conn;
	private Statement stmt;
	private String host, username, password, dbname;
	private int port;
	
	public SQLHander() throws ConfigurationException, ClassNotFoundException, SQLException {
		Server.logger.log("Checking db properties for credentials");
		Configuration config = Server.configs.properties(new File("properties/db.properties"));
		host = config.getString("host");
		port = config.getInt("port");
		username = config.getString("username");
		password = config.getString("password");
		dbname = config.getString("dbname");
		
		Class.forName("com.mysql.cj.jdbc.Driver");
		
		conn = DriverManager.getConnection("jdbc:mysql://"+ host + ":" + port + "/" + dbname + "?useSSL=false", username, password);
		stmt = conn.createStatement();
		
		// Verify tables
		
		Server.logger.log("Verifying SQL tables");
		
		// End verify tables
		
		Server.logger.log("Connected established: " + host);
	}
	
	public void addUser(User user) throws SQLException {
		PreparedStatement ps = conn.prepareStatement("INSERT INTO active_users (`uuid`, `key`) VALUES (?, ?)");
		ps.setString(1, user.getUUID());
		ps.setString(2, user.getSecret());
		ps.executeUpdate();
	}
	
	public User getUser(User user) throws SQLException {
		ArrayList<User> users = getActiveUsers();
		for(User u : users)
			if(user.getUUID().equals(u.getUUID()) && user.getSecret().equals(u.getSecret()))
				return u;
		return null;
	}
	
	public ArrayList<User> getActiveUsers() throws SQLException {
		ArrayList<User> users = new ArrayList<User>();
		ResultSet rs = stmt.executeQuery("SELECT * FROM active_users");
		while(rs.next())
			users.add(new User(rs.getString("uuid"), rs.getString("key")));
		return users;
	}
	
	public void stop() throws SQLException {
		Server.logger.log("Closing SQL connection");
		conn.close();
	}
	
}
