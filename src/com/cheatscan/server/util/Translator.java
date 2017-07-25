package com.cheatscan.server.util;

import java.io.IOException;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Translator {

	public static final String DELIMETER = "%";
	
	/**
	 * @deprecated
	 * % before and after variables
	 */
	public static Object[] regexToObject(String str, String regex) throws IOException {
		Pattern pattern = Pattern.compile(regex.replace(DELIMETER, ""));
		Matcher matcher = pattern.matcher(str);
		int count = 0;
		while(matcher.find())
			count++;
		if(count == 0)
			throw new IOException("Input string does not match regex");
		else if(count > 1)
			throw new IOException("Matches > 1");
		else {
			Pattern parse = Pattern.compile("\\" + DELIMETER + "([^" + DELIMETER + "]*)\\" + DELIMETER);
			Matcher parsed = parse.matcher(regex);
			ArrayList<String> tokens = new ArrayList<String>();
			while(parsed.find())
				tokens.add(parsed.group(1));
			String valueRegex = "^";
			for(int i = 0;i<tokens.size()-1;i++)
				valueRegex += "(" + tokens.get(i) + ").*";
			valueRegex += "(" + tokens.get(tokens.size()-1) + ")";
			Pattern values = Pattern.compile(valueRegex);
			Matcher matchedValues = values.matcher(str);
			matchedValues.find();
			String[] obj = new String[matchedValues.groupCount()];
			for(int i = 1;i<=matchedValues.groupCount();i++)
				obj[i-1] = matchedValues.group(i);
			
			Object[] objects = new Object[matchedValues.groupCount()];
			for(int i = 0;i<obj.length;i++) {
				try {
					objects[i] = Integer.parseInt(obj[i]);
				}
				catch(NumberFormatException e) {
					try {
						objects[i] = Long.parseLong(obj[i]);
					}
					catch(NumberFormatException e1) {
						try {
							objects[i] = Double.parseDouble(obj[i]);
						}
						catch(NumberFormatException e2) {
							objects[i] = obj[i];
						}
					}
				}
			}
			return objects;
		}
	}
	
	public static boolean validate(String str, String regex, int matches) {
		Matcher matcher = Pattern.compile(regex).matcher(str);
		int found = 0;
		while(matcher.find())
			found++;
		return (matches == -1 && found > 0) || (matches == found);
	}
	
	public static ArrayList<String> getMatches(String str, String regex) {
		ArrayList<String> matches = new ArrayList<String>();
		Matcher m = Pattern.compile(regex).matcher(str);
		while(m.find())
			matches.add(m.group());
		return matches;
	}
	
}