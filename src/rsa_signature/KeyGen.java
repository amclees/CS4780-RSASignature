package rsa_signature;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
// import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

public class KeyGen {
  public static final boolean noisy = true;
  
  private KeyGen() {}
  
  public static void main(String[] args) {
    BigInteger[] keys = getKeys();
    writeKeys(keys);
  }
  
  
  public static BigInteger[] getKeys() {
    return getKeys(1024);
  }
  
  /**
   * Gets RSA keys with n as the specified numberOfBits
   * @param numberOfBits Bits in n
   * @return BigInteger[] = { n, e, d }
   */
  public static BigInteger[] getKeys(int numberOfBits) {
    SecureRandom rand = new SecureRandom();
    if (numberOfBits <= 0 || !((numberOfBits & (numberOfBits - 1)) == 0)) {
      throw new IllegalArgumentException();
    }
    int factorLength = numberOfBits / 2;
    BigInteger p = null;
    BigInteger q = null;
    BigInteger n = null;
    boolean cont = true;
    while (cont) {
      p = new BigInteger(factorLength, Integer.MAX_VALUE, rand);
      q = new BigInteger(factorLength, Integer.MAX_VALUE, rand);
      n = p.multiply(q);
      BigInteger nConstraint = BigInteger.TEN.pow(50 * (int)Math.floor(((0.0f + numberOfBits) / 1024)));
      BigInteger pMinusQ = p.subtract(q).abs();
      cont = nConstraint.compareTo(pMinusQ) > 0;
      System.out.println(nConstraint);
      System.out.println(pMinusQ);
    }
    BigInteger totientN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)); // == totient(n)
    BigInteger e;
    do {
      e = new BigInteger(numberOfBits, rand);
    } while ((!totientN.gcd(e).equals(BigInteger.ONE)) || e.equals(BigInteger.ZERO));
    BigInteger d = e.modInverse(totientN);
    if (noisy) {
      System.out.printf("p: %d%nq: %d%nn: %d%ne: %d%nd: %d%ne * d mod totient(n): %d%ngcd(e, totient(n)): %d%n", p, q, n, e, d, e.multiply(d).mod(totientN), totientN.gcd(e));
    }
    return new BigInteger[] { n, e, d };
  }
  
  /**
   * Writes the keys in object form to pubkey.rsa and privkey.rsa. Each file has n written, followed by the key (e or d)
   * @param keys BigInteger[] in the form { n, e, d }
   * @throws IOException 
   */
  public static void writeKeys(BigInteger[] keys) {
    File publicKeyFile = new File("pubkey.rsa");
    File privateKeyFile = new File("privkey.rsa");
    ObjectOutputStream publicKeyOut = null;
    ObjectOutputStream privateKeyOut = null;
    try {
      publicKeyOut = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
      privateKeyOut = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
      publicKeyOut.writeObject(keys[0]);
      privateKeyOut.writeObject(keys[0]);
      publicKeyOut.writeObject(keys[1]);
      privateKeyOut.writeObject(keys[2]);
      if(noisy) {
        System.out.println("Wrote keys");
      }
    } catch (IOException e) {
      if(noisy) {
        System.out.println("Failed to write keys");
      }
    } catch (Exception e) {
      throw e;
    } finally {
      if (publicKeyOut != null) {
        try {
          publicKeyOut.close();
        } catch (IOException e) {
          // If this failed, the stream is already closed.
        }
      }
      if (privateKeyOut != null) {
        try {
          privateKeyOut.close();
        } catch (IOException e) {
          // If this failed, the stream is already closed.
        }
      }
    }
  }
}
