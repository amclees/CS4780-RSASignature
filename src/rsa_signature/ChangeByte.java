package rsa_signature;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Random;
import java.util.Scanner;

public class ChangeByte {
	private ChangeByte() {}

	public static void main(String[] args) {
		Scanner sc = new Scanner(System.in);
		System.out.print("Signed file to tamper with: ");
		String fileName = sc.next();
		
		if (!fileName.matches("^[\\w,\\s-]+\\.signed$")){
			System.out.println("That file is not valid (not a .signed). No tampers allowed.");
			return;
		}
		File tampFile = new File(fileName);
		byte[] tamperBinary = byteFetcher(tampFile);
		
		System.out.print("Byte (0-" + (tamperBinary.length-1) + ") to tamper: ");
		String rawInput = sc.next();
		while(!rawInput.matches("\\d+") || (Integer.parseInt(rawInput) < 0 || Integer.parseInt(rawInput) >= tamperBinary.length)){
			System.out.print("Enter an NUMBER between 0 and " + (tamperBinary.length-1) + ": ");
			rawInput = sc.next();
		}
		
		int bytePosition = Integer.parseInt(rawInput);
		
		tamperFile(tampFile,bytePosition,tamperBinary);
		
		sc.close();
		System.exit(0);
	}

	public static byte[] byteFetcher(File file) {
		if(!file.exists()){
			System.out.println("Cannot fetch bytes of nonexistant file!");
			return null;
		}
		// ObjectInputStream fileStream = null;
		BufferedInputStream fileStream = null;
		
		// size is related. Use length() of File obj
		// System.out.println(file.getName() + " size: " + file.length());
		byte[] binaryFile = new byte[(int)file.length()];
		
		try{
			fileStream = new BufferedInputStream(new FileInputStream(file));
			fileStream.read(binaryFile); // I feel like this is bad but I'm keeping it.
			fileStream.close();
			System.out.println("File has been read into binary array.");
			
			// System.out.println("binaryFile length: " + binaryFile.length);
//			for(int i = 0; i < 40; i++)
//				System.out.print(Integer.toBinaryString((binaryFile[i+1000] & 0xFF) + 0x100).substring(1) + " ");
//			System.out.println();
		} catch (IOException e) {
			System.out.println("Error opening file");
		}
		return binaryFile;
	}
	
	public static void tamperFile(File tamfile, int bytePos, byte[] binarray){
		byte[] randbyte = new byte[1];
		new Random().nextBytes(randbyte);
		
		while(randbyte[0] == binarray[bytePos])
			new Random().nextBytes(randbyte);
		
		System.out.println("\nChanging the marked byte:");
		
		// Aesthetics
		final int SIDERANGE = 2; // SIDERANGE > [BYTE BYTE] center [BYTE BYTE]
		int min = 0;
		if(binarray.length > SIDERANGE * 2 + 1){
			min = bytePos - (SIDERANGE);
			while(min < 0) min++;
			while(min + (SIDERANGE * 2) > binarray.length) min--;
		}
		String blank = "        ";
		String indic = "^^^^^^^^";
		
		for(int a = min; a < min + SIDERANGE * 2 + 1 &&  a < binarray.length; a++)
			if(a != bytePos) System.out.print(blank + " "); else { System.out.print(bytePos); break; }
		System.out.println();
		for(int i = min; i < min + SIDERANGE * 2 + 1 &&  i < binarray.length; i++)
			System.out.print(Integer.toBinaryString((binarray[i] & 0xFF) + 0x100).substring(1) + " ");
		System.out.println();
		for(int j = min; j < min + SIDERANGE * 2 + 1 &&  j < binarray.length; j++)
			if(j == bytePos) System.out.print(indic + " "); else System.out.print(blank + " ");
		System.out.println();
		
		binarray[bytePos] = randbyte[0];
		
		for(int k = min; k < min + SIDERANGE * 2 + 1 &&  k < binarray.length; k++)
			System.out.print(Integer.toBinaryString((binarray[k] & 0xFF) + 0x100).substring(1) + " ");
		System.out.println();
		try {
			OutputStream fileOut = null;
			try {
				fileOut = new BufferedOutputStream(new FileOutputStream(tamfile));
				fileOut.write(binarray);
			} finally {
				fileOut.close();
			}
		} catch (FileNotFoundException e) {
			System.out.println("No idea how this exception triggered as it should be impossible. " + e);
		} catch (IOException e) {
			System.out.println("IOException: " + e);
		}
		
		System.out.println("\nThe file has been tampered with at byte index " + bytePos + ".");
	}
}
