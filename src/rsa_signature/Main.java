package rsa_signature;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.util.Scanner;
import java.util.regex.Pattern;

import javafx.application.Platform;

public class Main {
  
  private Main() {}
  
  public static void main(String[] args) {
    Scanner sc = new Scanner(System.in);
    while (true) {
      System.out.printf("Actions:%n  0   Exit%n  1  \"Send\" files%n  2  \"Receive\" files%n");
      int action = sc.nextInt();
      if (action == 1) {
        System.out.println("Enter a filename:");
        String filename = sc.next();
        DigitalSignature.writeSigned(new File(filename), getKeys(true));
      } else if (action == 2) {
        System.out.println("Enter a filename that ends in \".signed\":");
        String filename = sc.next();
        if (!filename.matches(".*" + Pattern.quote(".") + "signed")) {
          System.out.println("That file is not valid (not a .signed)");
          continue;
        }
        boolean valid = DigitalSignature.verify(new File(filename), getKeys(false));
        System.out.printf("The file has %sbeen tampered with.%n", valid ? "not " : "");
      } else {
        break;
      }
    }
    // Fixes failure to cede resources after exit
    System.exit(0);
  }
  
  public static BigInteger[] getKeys(boolean privateKey) {
    File keyFile = new File(privateKey ? "privkey.rsa" : "pubkey.rsa");
    ObjectInputStream keyIn = null;
    
    BigInteger n = null;
    BigInteger exponent = null;
    try {
      keyIn = new ObjectInputStream(new FileInputStream(keyFile));
      n = (BigInteger) keyIn.readObject();
      exponent = (BigInteger) keyIn.readObject(); 
      if (KeyGen.noisy) {
        System.out.println("Read keys");
      }
    } catch(IOException e) {
      if(KeyGen.noisy) System.out.println("Failed to read keys");
    } catch(ClassCastException e) {
      e.printStackTrace();
    } catch (ClassNotFoundException e) {
      e.printStackTrace();
    } finally {
      if(keyIn != null) {
        try {
          keyIn.close();
        } catch(IOException e) {}
      }
    }
    BigInteger[] keys = { n, exponent };
    return keys;
  }
}
