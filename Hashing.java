import java.awt.List;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.ReadOnlyFileSystemException;
import java.util.ArrayList;
import java.util.Scanner;
import java.security.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import java.util.Base64;

public class Hashing {
	

	public static void main(String[] args) throws Exception {
		long start= System.nanoTime();
		// Instances
		ArrayList<String> allFiles=new ArrayList<String>();
		ArrayList<Files> allFileObjs=new ArrayList<Files>();
		byte[] s;
	
		int ctrlPoint ;
		String allWords="";
		// generate public and private keys
        KeyPair keyPair = buildKeyPair();
        Key pubKey = keyPair.getPublic();
        Key privateKey = keyPair.getPrivate();
        byte[] encodedBytespublic = Base64.getEncoder().encode(pubKey.getEncoded());
        byte[] encodedBytesPrivate = Base64.getEncoder().encode(privateKey.getEncoded());
  
      //Assignto MD5 
        if(args[9].equals("MD5")) {
			ctrlPoint = 0;
		}
		//Assignto SHA-512 
		else {
			ctrlPoint = 1;
		}
        ReadFile(args[3],allFiles);
		
		// Add file objects
		for(String a:allFiles) {
			Files nextFile=new Files(a);
			nextFile.HashWords(a,ctrlPoint);
			allFileObjs.add(nextFile);
		
		}
		String RegistrElements = "";
      //check if file contains data
      		File f = new File(args[5]);
      		if(f.exists() && !f.isDirectory()) { 
      			Scanner regScanner=new Scanner(new File(args[5]));
      			Scanner scanner = new Scanner(new File(args[11]));
      			Scanner scanner2=new Scanner(new File(args[12]));
      			String line="";
      			String line2="";
      			String lll="";
      			while(regScanner.hasNextLine()) {
     				lll+=regScanner.nextLine().toString();
     			 }
      			regScanner.close();
      			int signatureindex=lll.indexOf("Signature->");
      			String lastSign=lll.substring(signatureindex+11);
      			while(scanner.hasNextLine()) {
      				 line =line+ scanner.nextLine().toString();
      			 }
      			while(scanner2.hasNextLine()) {
     				 line2 =line2+ scanner2.nextLine().toString();
     			 }
      			regScanner.close();
      			scanner.close();
      			scanner2.close();
      		
      			PrivateKey privKey = getPrivateKey(line);
      			FileOutputStream registerOut = new FileOutputStream(args[5]);
      			for(Files wordsinFile:allFileObjs) {
        			registerOut.write((wordsinFile.path + " " + wordsinFile.getHashValue()).getBytes());
        			registerOut.write(System.getProperty("line.separator").getBytes());
        		}
      			Files registerHasValue=new Files(args[5]);
    			registerHasValue.HashWords(args[5], ctrlPoint);
          	  	
      			
      	       
    			PublicKey pubcKey=getPublicKey(line2);
    			
    			byte[] signature=encrypt(privKey, registerHasValue.hashValue);
    			registerOut.write("Signature->".getBytes());
    			//using public key for signatures
    			byte[] newSign=decrypt(pubcKey, signature);
    			byte[] lastSignD=decrypt(pubcKey, Base64.getDecoder().decode(lastSign.getBytes()));
    			//System.out.println(newSign.equals(lastSignD));
    			//
    			byte[] signBytes = Base64.getEncoder().encode(signature);
    			registerOut.write(signBytes);
    			registerOut.close();
    			FileOutputStream logOut = new FileOutputStream(args[7]);
    			if(new String(signBytes).equals(lastSign)) {
    				logOut.write("time stamp: verification correct".getBytes());

    			}
    			else {
    				logOut.write("time stamp: verification failed".getBytes());
    				registerOut.write(System.getProperty("line.separator").getBytes());
    				logOut.write(("time stamp:"+args[3]+" altered").getBytes());
    				
    			}
    		
      			
      		}else {
      		
      			FileOutputStream registerOut = new FileOutputStream(args[5]);
      			FileOutputStream out = new FileOutputStream(args[11]);
      	        FileOutputStream out2 = new FileOutputStream(args[12]);
      	        out2.write(encodedBytespublic);
      	        out.write(encodedBytesPrivate);
      	        out.close();
      	        out2.close();
      	  	for(Files wordsinFile:allFileObjs) {
    			registerOut.write((wordsinFile.path + " " + wordsinFile.getHashValue()).getBytes());    		
    			registerOut.write(System.getProperty("line.separator").getBytes());
    		}
      	  	
      	  	
      	  
			Files registerHasValue=new Files(args[5]);
			registerHasValue.HashWords(args[5], ctrlPoint);
			registerOut.write("Signature->".getBytes());
			byte[] signature=encrypt(privateKey, registerHasValue.hashValue);
			byte[] signBytes = Base64.getEncoder().encode(signature);
			registerOut.write(signBytes);
			registerOut.close();
      		}
       
        //System.out.println(pubKey.toString());
		
		// Control point of Hash Algorithm
		
		
		// Get all String Paths
	
		
	
		

		
		
	
		
	}
	
	// Add paths to String List
	public static ArrayList<String> ReadFile(String arg,ArrayList<String> aFile) {
		  File root = new File( arg );
		  
	      File[] list = root.listFiles();
	      if (list == null) return null;
	      for ( File f : list ) {
	            if ( f.isDirectory() ) {
	            	 ReadFile( f.getAbsolutePath(),aFile );
	            }
	            else {        	
	            	aFile.add(f.getAbsolutePath()); 
	            }
	        }
		return null;
		
	}
	
	// KEYPAIR
	public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
        final int keySize = 1024;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);      
        return keyPairGenerator.genKeyPair();
    }
	
	// Encrypt RSA
    public static byte[] encrypt(Key privateKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);  

        return cipher.doFinal(message.getBytes());  
    }
    
    // Decrypt RSA
    public static byte[] decrypt(Key publicKey, byte [] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        
        return cipher.doFinal(encrypted);
    }
    
    public static PrivateKey getPrivateKey(String key) throws Exception {
    	byte[] keyBytes = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec keySpec = new  PKCS8EncodedKeySpec(keyBytes); 
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec); 
        return privateKey;
    }
    public static PublicKey getPublicKey(String key) throws Exception {
    	byte[] keyBytes = Base64.getDecoder().decode(key);
        X509EncodedKeySpec keySpec = new  X509EncodedKeySpec(keyBytes); 
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publickey = keyFactory.generatePublic(keySpec); 
        return publickey;
    }

}
