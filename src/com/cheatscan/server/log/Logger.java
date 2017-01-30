package com.cheatscan.server.log;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

import com.cheatscan.server.Server;
import com.cheatscan.server.User;
import com.cheatscan.server.ViolationType;

// TODO: Handle all the try catches
public class Logger {
	
	private ArrayList<String> log;
	private File file;
	private BufferedWriter bw;
	private FileWriter fw;
	
	public Logger() {
		log = new ArrayList<String>();
		Runtime.getRuntime().addShutdownHook(new Thread() {
			public void run() {
				if(bw != null)
					try {
						bw.close();
					} catch (IOException e) {}
				if(fw != null)
					try {
						fw.close();
					} catch (IOException e) {}
			}
		});
	}
	
	public Logger(File file) {
		setFile(file);
	}
	
	public void log(String msg) {
		String message = new SimpleDateFormat("yy/MM/dd HH:mm:ss").format(new Date()) + ": " + msg;
		log.add(message);
		System.out.println(message);
		if(file != null)
			writeLineToFile(message);
	}
	
	public void createFile(File folder) {
		if(!folder.isDirectory() && folder.isFile())
			;
		else if(folder.isDirectory() || folder.mkdir()) {
			String fileName = new SimpleDateFormat("yy-MM-dd HH-mm-ss").format(new Date()) + ".txt";
			File file = new File(folder.getAbsoluteFile() + File.separator + fileName);
			try {
				file.createNewFile();
			} catch (IOException e1) {
				e1.printStackTrace();
			}
			setFile(file);
		}
		else {
			;
		}
	}
	
	private void setFile(File file) {
		this.file = file;
		try {
			fw = new FileWriter(file, true);
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		bw = new BufferedWriter(fw);
		if(log == null)
			log = new ArrayList<String>();
		else {
			for(String s : log)
				writeLineToFile(s);
		}
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
	
	private void writeLineToFile(String s) {
		if(file == null)
			return;
		try {
			bw.write(s + "\r\n");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
}
