import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.zip.GZIPOutputStream;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class Server {
	public static void main(String[] args) {
		

		try {
			
			KeyPair kpg=generateKeys();
			PublicKey pub = kpg.getPublic();
			PrivateKey pvt = kpg.getPrivate();
			SecretKey session = generateSessionKey();
			
			SecureRandom srandom=new SecureRandom();
			byte ivArr[] = new byte[16];
			srandom.nextBytes(ivArr); 
			IvParameterSpec iv = new IvParameterSpec(ivArr);
			
			// open port 8080
			int port=8080;
			ServerSocket s = new ServerSocket(port);
			System.out.println("Server opens port " + port );
			//Accept client connection
			Socket clientSocket = s.accept();
			System.out.println("Server: Connection Established!");
			
			DataInputStream dis = new DataInputStream(clientSocket.getInputStream());
			DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream());
			
			//read from client, find header
			String header=getHeader(dis);
			System.out.println(header);
			
			//find desired file name in header
			String file=findFileName(header);
			System.out.println("filename: " + file);
			PublicKey clientPub = getClientPublicKey(dis);
			
			//send server public key
			dos.write(pub.getEncoded());
			dos.flush();
			
			//send session key encrypted with client's public key
			dos.write(encrypt(clientPub,session.getEncoded()));
			dos.flush();
			
			//send iv encrypted with client's public key
			byte[] a=encrypt(clientPub,ivArr);
			
			dos.write(a);
			dos.flush();
		
			//open destination file
			File f= new File(System.getProperty("user.dir")+"\\"+file);
			
			if (f.exists()) {
				
				FileInputStream fis = new FileInputStream(file);
				byte[] chunk = new byte[128000]; // 125 KB chunks
				int len;
				
				while(( len=fis.read(chunk))!= -1) {
					byte[] chnk=Arrays.copyOfRange(chunk, 0, len);
					
					//get hash of the data
					byte[] hash=hashData(chnk);
					
					//encrypt hash with private key
					byte [] encHash= encrypt(pvt,hash);
					
					//concatenate data and the hash
					byte[] totalData= concatenate(encHash,chnk);
					
					//compress the total data
					byte[] compressedData=compress(totalData);

					//encrypt compressedData
					byte[] data = encrypt(session,iv,compressedData);

					byte[] responseHeader = constructHeader(data.length);
					
					//send response header and the data
					dos.write(responseHeader);
					dos.flush();
					dos.write(data);
					dos.flush();
				}
				
				fis.close();
				System.out.println("Data sent successfully!");
				dos.close();
				clientSocket.close();
				s.close();
				
			}
			
		
		} catch (Exception e) {
			
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
	
	public static SecretKey generateSessionKey()  {
		
		KeyGenerator kgen;
		try {
			
			kgen = KeyGenerator.getInstance("AES");
			kgen.init(256);
			
			return kgen.generateKey();
			
		} catch (NoSuchAlgorithmException e) {
			
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
	
	public static byte[] encrypt(PrivateKey privateKey, byte[] data) {
        try {
           
        	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return cipher.doFinal(data);
            
        } 
        catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
	public static byte[] encrypt(PublicKey publicKey, byte[] data) {
        try {
           
        	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        	
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] a= cipher.doFinal(data);
            return a;
            
        } 
        catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
	
	public static byte[] encrypt(SecretKey session,IvParameterSpec iv,byte[] data) {
		
		Cipher ci;
		try {
			ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			ci.init(Cipher.ENCRYPT_MODE, session, iv);	
			byte[] a=ci.doFinal(data);
			return  a;
		} 
		catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException  | InvalidAlgorithmParameterException 
				| IllegalBlockSizeException | BadPaddingException  e) {
			
			e.printStackTrace();
		}
		
		return null;
	}
	
	
	
	public static byte[] compress(byte[] bytes) throws IOException {
		
	        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
	        GZIPOutputStream gzos = new GZIPOutputStream(byteArrayOutputStream);
	        gzos.write(bytes);
	        gzos.close();
	        byte[] compressedBytes = byteArrayOutputStream.toByteArray();
	        byteArrayOutputStream.close();
	        
	        return compressedBytes;
	    
	}
	
	public static String getHeader(DataInputStream dIS) throws IOException {
		byte[] headerArr = new byte[5000];
		int hc = 0;

		// only for header part
		while (true) {
			byte i = (byte) dIS.read();
			headerArr[hc++] = i;
			if (headerArr[hc - 1] == '\n' && headerArr[hc - 2] == '\r' && headerArr[hc - 3] == '\n'
					&& headerArr[hc - 4] == '\r') { // \r\n\r\n
				break;
			}

		}
		return new String(headerArr, 0, hc);
	}
	
	public static String findFileName(String header) {
		
		int fsp = header.indexOf('/');
		int ssp = header.indexOf(' ', fsp + 1);
		
		return header.substring(fsp + 1, ssp);
	}
	
	public static byte[] concatenate(byte[] hash, byte[] data) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		try {
			outputStream.write( hash );
			outputStream.write( data );
	
		} catch (IOException e) {
			
			e.printStackTrace();
		}
		return outputStream.toByteArray( );
		
	}
	
	public static PublicKey getClientPublicKey(DataInputStream dis) {
		
		byte[] bytes= new byte[294];
		
		try {
			dis.read(bytes);
			KeyFactory kf = KeyFactory.getInstance("RSA"); 
			return  kf.generatePublic(new X509EncodedKeySpec(bytes));
		} 
		catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			
			e.printStackTrace();
		}
		return null;
	}
	
	public static byte[] constructHeader(int dataLength) {
		
		String responseHeader =	"HTTP/1.1 200 OK\r\n" +
				"Server: localhost\r\n" +
				"Content-Length: " + dataLength + "\r\n" +
				"\r\n";
		
		return responseHeader.getBytes();
	}
	
}
