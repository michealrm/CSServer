package com.cheatscan.server.socket;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Map;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

import com.cheatscan.server.Constants;
import com.cheatscan.server.Server;
import com.cheatscan.server.User;
import com.cheatscan.server.ViolationType;
import com.cheatscan.server.util.AES;
import com.cheatscan.server.util.Translator;
import com.esotericsoftware.yamlbeans.YamlReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CityResponse;

public class HandshakeProtocol implements Runnable {

	public static final String DELIMETER = "/:/";
	public static final String INSECURE = "$";
	public static final double TEXT_DETECTION_THRESHOLD = .3;
	
	private Socket socket;
	private DataOutputStream out;
	private String key;
	private ArrayList<SocketInputEvent> events;
	private boolean verified;
	private YamlReader reader;
	
	private User user;
	
	public HandshakeProtocol(Socket socket) {
		verified = false;
		this.socket = socket;
		events = new ArrayList<SocketInputEvent>();
		try {
			out = new DataOutputStream(socket.getOutputStream());
		} catch (IOException e) {
			Server.logger.socketLog(Server.getSocketIndex(socket)+1, "Closing connection with " + socket.getRemoteSocketAddress());
			return;
		}
		try {
			reader = new YamlReader(new FileReader(Server.detections));
		} catch (FileNotFoundException e) {}
	}
	
	public Socket getSocket() {
		return socket;
	}
	
	public String getKey() {
		return key;
	}

	public void run() {
		BufferedReader inFromClient = null;
		try {
			inFromClient = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		} catch (Exception e) {
			Server.logger.socketLog(Server.getSocketIndex(socket)+1, "Closing connection with " + socket.getRemoteSocketAddress());
			try {
				socket.close();
			} catch (IOException e1) {
				Server.logger.log("Could not close socket. " + e1.getMessage());
			}
			return;
		}
		while(true) {
			// TODO: Use Translator.validate to validate input
			try {
				String string = inFromClient.readLine();
				if(string == null)
					throw new Exception();
				String in;
				boolean insecure = false;
				if(!string.startsWith(INSECURE) && !verified)
					throw new Exception();
				if(string.startsWith(INSECURE)) {
					insecure = true;
					in = string.substring(1);
				}
				else
					in = AES.decrypt(string, key); // Should always be verified, thus we should always have a key
	            
				boolean verUpdated = false;
	            if(!verified && insecure) {
	            	// Update verification
	            	if(in.contains(DELIMETER) && in.split(DELIMETER).length == 2) {
	            		String[] userInput = in.split(DELIMETER);
	            		user = Server.sql.getUser(new User(userInput[0], userInput[1])); // uuid:token
	            		if(user != null) {
	            			key = user.getSecret();
	            			verified = true;
	            			verUpdated = true;
	            			Server.logger.socketLog(Server.getSocketIndex(socket)+1, "Verified user with UUID: \"" + user.getUUID() + "\"");
	            			// Send scan.dll here
	            		}
	            	}
	            }
				//String in = string;
	            Server.logger.socketLog(Server.getSocketIndex(socket)+1, "[in] " + (insecure ? "[INSECURE] " : "") + in);
	            for(SocketInputEvent e : events)
	            	e.onInput(in, this);
	            
	            ////////////////
	            ///// SCAN /////
	            ////////////////
	            if(user != null && !verUpdated) {
	            	switch(user.getIndex()) {
	            		case 0: // Check system clock time
	            			ViolationType vtTime = ViolationType.SUSPICIOUS_TIME;
	            			
	            			// Expected input: "hh:mm:ss MM/dd/yyyy"
	            			if(!Translator.validate(in, "\\d{2}:\\d{2}:\\d{2} \\d{2}\\/\\d{2}\\/\\d{4}", 1)) {
	            				Server.vHandler.onUnexpectedInput(vtTime, in, user, socket);
	            				break;
	            			}
	            			ArrayList<String> obj = Translator.getMatches(in, "\\d{4}|\\d{2}");
	            			int hour = Integer.parseInt(obj.get(0));
	            			int min = Integer.parseInt(obj.get(1));
	            			int sec = Integer.parseInt(obj.get(2));
	            			int month = Integer.parseInt(obj.get(3));
	            			int day = Integer.parseInt(obj.get(4));
	            			int year = Integer.parseInt(obj.get(5));
	            			
	            			Calendar local = Calendar.getInstance();
	            			local.set(year, month, day, hour, min, sec);
	            			
	            			CityResponse response = null;
	            			try {
	            				response = Server.geoIPDB.city(((InetSocketAddress)socket.getRemoteSocketAddress()).getAddress()); // Client's IP
	            			}
	            			catch(IOException | GeoIp2Exception e) {
	            				Server.logger.exceptionLog("Couldn't resolve IP. Skipping time check.", e);
	            				break;
	            			}
	            			Calendar location = Calendar.getInstance(TimeZone.getTimeZone(response.getLocation().getTimeZone()));
	            			
	            			long difference = location.getTimeInMillis() - local.getTimeInMillis();
	            			if(difference > Constants.SUSPICIOUS_TIME_THRESHOLD) {
	            				boolean detectedInEventLog = false;
	            				// Check event log
	            				String sb = "";
	            				long dDays = TimeUnit.MILLISECONDS.toDays(difference);
	            				long dHours = TimeUnit.MILLISECONDS.toHours(difference);
	            				long dMins = TimeUnit.MILLISECONDS.toMinutes(difference);
	            				long dSeconds = TimeUnit.MILLISECONDS.toSeconds(difference);
	            				if(dDays != 0) {
	            					sb += dDays + " day";
	            					if(dDays != 1)
	            						sb += "s, ";
	            					else
	            						sb += ", ";
	            				}
	            				if(dHours != 0) {
	            					sb += dHours + " hour";
	            					if(dHours != 1)
	            						sb += "s, ";
	            					else
	            						sb += ", ";
	            				}
	            				if(dMins != 0) {
	            					sb += dMins + " minute";
	            					if(dMins != 1)
	            						sb += "s, ";
	            					else
	            						sb += ", ";
	            				}
	            				sb += dSeconds + " second" + (dSeconds == 1 ? "" : "s");
	            				Server.vHandler.onViolation(vtTime, "Time is " + (difference >= 0 ? "positively" : "negatively") + " offset by " + sb, "Local machine time did not coordinate with the real time.", detectedInEventLog ? 1.0 : 5.0, 1.0, user, socket);
	            			}
	            			
	            			user.setIndex(user.getIndex()+1);
	            			
	            			break;
	            			
	            		case 111: // Send heuristic.dll (scan whole system/dll with all the blacklists)
	            			// Send client DOS blacklist via TCP
	            			// Reserved for SUSPICIOUS.HEURISTIC (event log maybe?, event log for event id 1)
	            		case 5: // Checks malicious package names in JVM
	            			// Expected input: "package1","package2","package3","package4"
	            			if(!Translator.validate(in, "(?<=(?:^|,)\")(?:[^\"]|\"\")+", -1)) {
	            				Server.vHandler.onUnexpectedInput(ViolationType.CHEAT_HEURISTIC, in, user, socket);
	            				break;
	            			}
	            			ArrayList<String> cLines = Translator.getMatches(in, "(?<=(?:^|,)\")(?:[^\"]|\"\")+");
                   		 String[] clientLines = in.split(","); // Check to make sure this isn't BS
                   		 Map check;
                   		 boolean detActive = false;
                   		 boolean detected = false;
                   		 while((check = (Map)reader.read()) != null) {
                   			 if(!((String)check.get("type")).equals("package"))
                   				 continue;
                   			 ArrayList<String> str = (ArrayList<String>)check.get("text");
                   			 int matchedLines = 0;
                   			 int lines = str.size();
                   			 for(String n : clientLines)
                   				 for(String v : str)
                   					 if(n.equals(v))
                   						 matchedLines++;
                   			 double matched = (double)matchedLines / lines;
                   			 if(matched > TEXT_DETECTION_THRESHOLD && !detActive) {
                   				 detected = true;
                   				 Server.logger.scanLog(Server.getSocketIndex(socket)+1, user, "Detected " + (String)check.get("admin_name") + " with a " + matched + " chance");
                   				 out.writeBytes("Detected " + (String)check.get("admin_name") + " with a " + matched + " chance\n");
                   				 if(((String)check.get("admin_name")).contains("Active"))
                   					 detActive = true;
                   			 }
                   		 }
                   		 if(!detected)
                   			 out.writeBytes("clean\n");
                   		 user.setIndex(user.getIndex()+1);
                   		 break;
	            	}
	            }
			} catch (Exception e) {
				Server.logger.socketLog(Server.getSocketIndex(socket)+1, "Closing connection with " + socket.getRemoteSocketAddress() + " because " + e.getMessage());
				try {
					socket.close();
				} catch (IOException e1) {
					Server.logger.log("Could not close socket. " + e1.getMessage());
				}
				return;
			}
		}
	}
	
	public void addSocketInputEvent(SocketInputEvent event) {
		events.add(event);
	}
	
	public boolean removeSocketInputEvent(SocketInputEvent event) {
		return events.remove(event);
	}
	
	public void printRaw(String msg) throws IOException {
		out.writeBytes(msg);
	}
	
	public void print(String msg) throws IOException {
        print(key, msg);
	}
	
	public void print(String key, String msg) throws IOException {
		out.writeBytes(AES.encrypt(msg, key));
		Server.logger.socketLog(Server.getSocketIndex(socket)+1, "[out] " + msg);
	}
	
}
