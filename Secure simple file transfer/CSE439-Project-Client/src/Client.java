import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Scanner;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;

public class Client {
		
		public static void main(String[] args) {
			try {
				
				Scanner scan = new Scanner(System.in);  // Create a Scanner object
			    System.out.print("Enter filename:");
			    String file = scan.nextLine();
			    
			    if( ! checkFile(file) ) { //check if file exists
			    	System.out.println("FILE DOES NOT EXIST!");
			    	System.exit(0);
			    }
				
				
				KeyPair kpg=generateKeys();
				PublicKey pub = kpg.getPublic();
				PrivateKey pvt = kpg.getPrivate();
				
				Socket connectionSocket = new Socket("localhost", 8080);
				System.out.println("Client: Connection Established!");
				
				DataInputStream dIS = new DataInputStream(connectionSocket.getInputStream());
				DataOutputStream dOS = new DataOutputStream(connectionSocket.getOutputStream());
			    
				String request = "GET /"+ file + " HTTP/1.1\r\nHost: localhost\r\n"+"\r\n";
				
				long start,stop; 
				start=System.currentTimeMillis(); //start the timer to measure the duration
				
				// send HTTP request to server
				dOS.write(request.getBytes());
				dOS.flush();
				
				//send public key to server 
				dOS.write(pub.getEncoded());
				dOS.flush();
				
				//read server's public key
				PublicKey serverPub = getServerPublicKey(dIS);
				//get the encrypted session key and decrypt it
				SecretKey session = getSessionKey(dIS,pvt);
				IvParameterSpec iv = getIv(dIS,pvt);
				
				//create file
				File f= new File(file);
				f.createNewFile();
				FileOutputStream fos=new FileOutputStream(file,true);
				
				String header;
				int len;
				int contSize;
				byte[] chunk;
				
				while( ( header = getHeader(dIS) ) != null) {
					
					contSize = getContentSize(header);
					chunk=new byte[contSize];
				
					len=dIS.read(chunk);
					byte[] chnk=Arrays.copyOfRange(chunk, 0, len);
					
					//decrypt the data
					byte[] compressedData=decrypt(chnk,session,iv);
					
					//decompress the data
					byte[] totalData = decompress(compressedData);

					//get the hash part from message
					byte[] hash = getHash(Arrays.copyOfRange(totalData, 0, 256),serverPub);

					//get the data part from message
					byte[] data = Arrays.copyOfRange(totalData, 256, totalData.length);

					//Compare hash and the hash of the obtained data to see if it is modified
					if (Arrays.equals(hash, hashData(data))) {

						fos.write(data);
					}
					else {
						System.out.println("WARNING: Packet is modified!");
					}
				}
				dOS.close();
				fos.close();
				connectionSocket.close();
				
				System.out.println("Data received successfully!");
				stop=System.currentTimeMillis();
				
				double time=((double)stop-start)/1000;
				System.out.println("duration: "+ time +" seconds");
			} 
			catch (IOException e) {
				
				e.printStackTrace();
			}
		}
		
		public static KeyPair generateKeys() {
			KeyPairGenerator kpg;
			try {
				
				kpg = KeyPairGenerator.getInstance("RSA");
				kpg.initialize(2048);
				return kpg.generateKeyPair();
				
			} catch (NoSuchAlgorithmException e) {

				e.printStackTrace();
			}
			return null;
		}
		
		public static SecretKey getSessionKey(DataInputStream dIS, PrivateKey prvt) {
			byte[] bytes = new byte[256];
			
			try {
				
				dIS.read(bytes);
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.DECRYPT_MODE, prvt);
				byte[] sessionArr=cipher.doFinal(bytes);
				
				return new SecretKeySpec(sessionArr,"AES");
			} 
			catch (Exception e) {
				
				e.printStackTrace();
			}
			return null;			
			
		}
		public static IvParameterSpec getIv(DataInputStream dIS, PrivateKey prvt) {
			byte[] bytes = new byte[256];
			
			try {
				dIS.read(bytes);
				
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.DECRYPT_MODE, prvt);
				byte[] ivArr=cipher.doFinal(bytes);
				return new IvParameterSpec(ivArr);
			}
			catch(Exception e) {
				e.printStackTrace();
			}
			return null;
		}
		
		public static PublicKey getServerPublicKey(DataInputStream dis) {
			
			byte[] bytes= new byte[294];
			PublicKey a;
			try {
				dis.read(bytes);
				KeyFactory kf = KeyFactory.getInstance("RSA"); 
				a=kf.generatePublic(new X509EncodedKeySpec(bytes));
				return a;
			} 
			catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
				
				e.printStackTrace();
			}
			return null;
		}
		
		public static byte[] decrypt(byte[] data,SecretKey session,IvParameterSpec iv) {
			
			Cipher ci;
			try {
				ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
				ci.init(Cipher.DECRYPT_MODE, session, iv);
				
				byte [] a=ci.doFinal(data);
				
				return a;
			} 
			catch(Exception e) {
				e.printStackTrace();
				System.out.println(data.length);
			}
			
			return null;
		}
		public static byte[] decompress(byte[] compressedData) {
		
			try {
				ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(compressedData);
				GZIPInputStream gis = new GZIPInputStream(byteArrayInputStream);
				ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
				
				byte[] buffer = new byte[1024];
	            int length;
	            while ((length = gis.read(buffer)) != -1) {
	                byteArrayOutputStream.write(buffer, 0, length);
	            }
	            gis.close();
	            return byteArrayOutputStream.toByteArray();
			} 
			catch (IOException e) {
				
				e.printStackTrace();
			}
		   return null;
		}
		
		public static byte[] getHash(byte[] data, PublicKey pub) {
			
			try {
				
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.DECRYPT_MODE, pub);
				byte[] a = cipher.doFinal(data);
				return a;
			} 
			catch ( NoSuchAlgorithmException  | NoSuchPaddingException | InvalidKeyException 
					| IllegalBlockSizeException | BadPaddingException e) {
				
				e.printStackTrace();
			}
			return null;			
			
		}
		
		public static byte[] hashData(byte[] data) {
			MessageDigest md;
			try {
				
				md = MessageDigest.getInstance("SHA-1");
				md.update(data);
				
				return md.digest();
			
			} catch (NoSuchAlgorithmException e) {
				
				e.printStackTrace();
			}
			return null;
		}
		
		public static String getHeader(DataInputStream dIS) throws IOException {
			byte[] headerArr = new byte[5000];
			int hc = 0;
			int flag=0;
			
			byte i;
			while ((i = (byte) dIS.read()) !=-1) { 
				headerArr[hc++] = i;
				if (headerArr[hc - 1] == '\n' && headerArr[hc - 2] == '\r' && headerArr[hc - 3] == '\n'
						&& headerArr[hc - 4] == '\r') { // \r\n\r\n
					flag=1;
					break;
				}

			}
			if ( flag == 0) {
				return null;
			}
			return new String(headerArr, 0, hc);
		}
		public static int getContentSize(String header) {
			
			int contIndex = header.indexOf("Content-Length: ");
			int eol2 = header.indexOf("\r\n", contIndex);
			String contSize = header.substring(contIndex + 16, eol2);
			
			return Integer.parseInt(contSize);
			
		}
		
		public static boolean checkFile(String file) {
			System.out.println(file);
			File f= new File(System.getProperty("user.dir")+"\\"+file);
			StringBuilder sb=new StringBuilder(f.getParent());  
		    sb.reverse();  
		    String reverse=sb.toString();
		    
		    int index=reverse.indexOf('\\');
		    String modReverse=reverse.substring(index+1,reverse.length());
		    sb=new StringBuilder(modReverse);
		    sb.reverse();
		    String reverse2 = sb.toString();
		    String path=reverse2+"\\Server\\" + file;
		    File f1=new File(path);
		    System.out.println(path);
		    return f1.exists();
		}
}


