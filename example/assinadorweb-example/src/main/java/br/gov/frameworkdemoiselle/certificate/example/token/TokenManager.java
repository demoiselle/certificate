package br.gov.frameworkdemoiselle.certificate.example.token;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Logger;

//Nesse exemplo gerenciamos em memória, mas ele pode ser gerenciado em banco e com timeout
public class TokenManager {
	
	private static Map<String,  Map<String, String>> map = Collections.synchronizedMap(new HashMap<String, Map<String, String>>());
	private static final Logger LOGGER = Logger.getLogger(TokenManager.class.getName());

	public static String put(Map<String, String> files) {
		String token = UUID.randomUUID().toString();

		map.put(token,files);
		return token;
	}

	public static Map<String, String> get(String token) {
		return map.get(token);
	}

	public static void invalidate(String token) {
		map.remove(token);
	}
	
	public static boolean isValid(String token){
		return map.containsKey(token);
	}

	public static String hash(java.nio.file.Path path) throws IOException {
		
		File file = new File(path.toString());
	    FileInputStream inputStream = null;

	    try {
	        MessageDigest md = MessageDigest.getInstance("SHA-512");
	        inputStream = new FileInputStream(file);
	        FileChannel channel = inputStream.getChannel();

	        long length = file.length();
	        if(length > Integer.MAX_VALUE) {
	            // you could make this work with some care,
	            // but this code does not bother.
	            throw new IOException("File "+file.getAbsolutePath()+" is too large.");
	        }

	        ByteBuffer buffer = channel.map(MapMode.READ_ONLY, 0, length);

	        int bufsize = 1024 * 8;          
	        byte[] temp = new byte[bufsize];
	        int bytesRead = 0;

	        while (bytesRead < length) {
	            int numBytes = (int)length - bytesRead >= bufsize ? 
	                                         bufsize : 
	                                         (int)length - bytesRead;
	            buffer.get(temp, 0, numBytes);
	            md.update(temp, 0, numBytes);
	            bytesRead += numBytes;
	        }

	        byte[] mdbytes = md.digest();

			StringBuilder sb = new StringBuilder();
			for(int i=0; i< mdbytes.length ;i++){
				sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			String generatedHash = sb.toString();
			
	        return generatedHash;

	    } catch (NoSuchAlgorithmException e) {
	        throw new IllegalArgumentException("Unsupported Hash Algorithm.", e);
	    } finally {
	        if(inputStream != null) {
	            inputStream.close();
	        }
	    }
	}
	
}
