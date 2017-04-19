package rsa_signature;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class DigitalSignature {
  public static final int bufferSize = 1024;
  
  public static void writeSigned(File file, BigInteger[] publicKey) {
    if(!file.isFile()) throw new IllegalArgumentException();
    File signedFile = null;
    try {
      signedFile = new File(file.getCanonicalPath() + ".signed");
      signedFile.createNewFile();
    } catch(IOException e) {
      if(KeyGen.noisy) System.out.println("Failed to make signed file path");
    }
    
    MessageDigest messageDigest = null;
    try {
      messageDigest = MessageDigest.getInstance("MD5");
    } catch (NoSuchAlgorithmException e) {
      System.out.println("Your JVM is broken, MD5 is guaranteed to be an algorithm.");
    }
    
    try {
      InputStream fileInput = new BufferedInputStream(new FileInputStream(file));
      for (int got = 1; got > 0;) {
        int left = fileInput.available();
        byte[] read = new byte[left < bufferSize ? left : bufferSize];
        got = fileInput.read(read, 0, read.length);
        messageDigest.update(read);
      }
      fileInput.close();
    } catch(IOException e) {
      if(KeyGen.noisy) System.out.println("Failed to get file bytes");
    }
    
    byte[] digestBytes = messageDigest.digest();
    BigInteger digest = new BigInteger(1, digestBytes);
    
    BigInteger signature = digest.modPow(publicKey[1], publicKey[0]);
    
    try {
      ObjectOutputStream signedFileOut = new ObjectOutputStream(new FileOutputStream(signedFile));
      signedFileOut.writeObject(signature);
      
      
      InputStream fileInput = new BufferedInputStream(new FileInputStream(file));
      for (int got = 1; got > 0;) {
        int left = fileInput.available();
        byte[] read = new byte[left < bufferSize ? left : bufferSize];
        got = fileInput.read(read, 0, read.length);
        signedFileOut.write(read);
      }
      fileInput.close();
      
      
      signedFileOut.close();
    } catch(IOException e) {
      if(KeyGen.noisy) System.out.println("Failed to write signed file");
    }
  }
  
  public static boolean verify(File file, BigInteger[] privateKey) {
    return false;
  }
  
}
