package com.cheatscan.server.util;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
 
public class AES {
 
    private static SecretKeySpec setKey(String myKey) 
    {
        try {
        	byte[] key;
            key = myKey.getBytes("UTF-8");
            key = Arrays.copyOf(key, 16); 
            return new SecretKeySpec(key, "AES");
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
		return null;
    }
 
    public static String encrypt(String strToEncrypt, String secret) 
    {
        try
        {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, setKey(secret));
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } 
        catch (Exception e) {}
        return null;
    }
 
    public static String decrypt(String strToDecrypt, String secret) 
    {
        try
        {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, setKey(secret));
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } 
        catch (Exception e) {}
        return null;
    }
}