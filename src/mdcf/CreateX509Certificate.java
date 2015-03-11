package mdcf;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;


public class CreateX509Certificate {

	/** 
	 * Creating a self-signed X.509 Certificate
	 * @param dn the X.509 Distinguished Name, eg "CN=ashwin, L=manhattan, C=US"
	 * @param pair the KeyPair
	 * @param days how many days from now the Certificate is valid for
	 * @param algorithm the signing algorithm, eg "SHA1withRSA"
	 */ 
	public X509Certificate generateCertificate(String dn, int days, String algorithm)
	  throws GeneralSecurityException, IOException
	{
		FileInputStream keyfis = new FileInputStream("Caprivatekey");
		byte[] encKey = new byte[keyfis.available()];  
		keyfis.read(encKey);
		keyfis.close();
		PKCS8EncodedKeySpec prKeySpec = new PKCS8EncodedKeySpec(encKey);
		KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
		PrivateKey caPrivateKey = keyFactory.generatePrivate(prKeySpec);
		
		keyfis = new FileInputStream("Capublickey");
		encKey = new byte[keyfis.available()];  
		keyfis.read(encKey);
		keyfis.close();
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
		keyFactory = KeyFactory.getInstance("DSA", "SUN");
		PublicKey caPublicKey = keyFactory.generatePublic(pubKeySpec);
		
		
	  X509CertInfo info = new X509CertInfo();
	  
	  
	  Date from = new Date();
	  //check if this is indeed valid!!
	  Date to = new Date(from.getTime() + days * 86400000l);
	  CertificateValidity interval = new CertificateValidity(from, to);
	  BigInteger sn = new BigInteger(64, new SecureRandom());
	  X500Name owner = new X500Name(dn);
	 
	  info.set(X509CertInfo.VALIDITY, interval);
	  info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
	  info.set(X509CertInfo.SUBJECT,owner);
	  info.set(X509CertInfo.ISSUER,owner);
	  info.set(X509CertInfo.KEY, new CertificateX509Key(caPublicKey));
	  info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
	  AlgorithmId algo = new AlgorithmId(AlgorithmId.sha1WithDSA_oid);
	  info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
	 
	  // Sign the cert to identify the algorithm that's used.
	  X509CertImpl newcert = new X509CertImpl(info);
	  newcert.sign(caPrivateKey, algorithm);
	  
	 
	  // Update the algorithm, and resign.
	  algo = (AlgorithmId)newcert.get(X509CertImpl.SIG_ALG);
	  info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
	  newcert = new X509CertImpl(info);
	  newcert.sign(caPrivateKey, algorithm);
	  return newcert;
	}   
	
	public KeyPair generateKeyPair(String algorithm){
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("DSA");
			keyGen.initialize(1024);
		    KeyPair keypair = keyGen.genKeyPair();
		    return keypair;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;  
	}
	
	public void pushToFile(X509Certificate cert){
		try {
			File file = new File("sample1.pem");
		    byte[] buf = cert.getEncoded();
		    
		  

		    FileOutputStream os = new FileOutputStream(file);
		    os.write(buf);
		
		    Writer wr = new OutputStreamWriter(os, Charset.forName("UTF-8"));
		    wr.write(new sun.misc.BASE64Encoder().encode(buf));
		    wr.flush();
		    os.close();

		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
	}

	public X509Certificate generate() {
		// TODO Auto-generated method stub
		
		try {
			String keyAlgorithm="DSA";
			String dn = "CN=ashwin, L=manhattan, ST=KS, C=US";
			//KeyPair keypair = generateKeyPair(keyAlgorithm);
			X509Certificate cert = generateCertificate(dn,30,"SHA1withDSA");
			System.out.println("successfull execution");
			
			return cert;
			
		} catch (GeneralSecurityException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
		
	}
	
	
	
	
}
