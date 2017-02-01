package com.java.test;

import com.cheatscan.server.util.Translator;

public class TranslatorTest {

	public static void main(String[] args) {
		String regex = "(?<=(?:^|,)\")(?:[^\"]|\"\")+";
		String str = "\"hello\",\"darkness\",\"nope\"";
		System.out.println(Translator.validate(str, regex, -1));
		System.out.println(str);
		System.out.println(Translator.getMatches(str, regex));
		
		
		String date = "12:11:30 11/12/2016";
		if(!Translator.validate(date, "\\d{2}:\\d{2}:\\d{2} \\d{2}\\/\\d{2}\\/\\d{4}", 1)) {
			System.out.println("Could not validate");
		}
		System.out.println(Translator.getMatches(date, "\\d{4}|\\d{2}"));
	}
	
}
