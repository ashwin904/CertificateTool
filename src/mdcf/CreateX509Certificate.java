package mdcf;

import sun.security.x509.*;

import java.security.cert.*;
import java.security.*;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.Date;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;


public class CreateX509Certificate {

	/** 
	 * Creating a self-signed X.509 Certificate
	 * @param dn the X.509 Distinguished Name, eg "CN=ashwin, L=manhattan, C=US"
	 * @param pair the KeyPair
	 * @param days how many days from now the Certificate is valid for
	 * @param algorithm the signing algorithm, eg "SHA1withRSA"
	 */ 
	public X509Certificate generateCertificate(String dn, KeyPair pair, int days, String algorithm)
	  throws GeneralSecurityException, IOException
	{
		
	  PrivateKey caPrivateKey = pair.getPrivate();
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
	  info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
	  info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
	  AlgorithmId algo = new AlgorithmId(AlgorithmId.sha1WithDSA_oid);
	  info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
	 
	  // Sign the cert to identify the algorithm that's used.
	  X509CertImpl newcert = new X509CertImpl(info);
	  newcert.sign(caPrivateKey, algorithm);
	 
	  // Update the algorithm, and resign.
//	  algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
//	  info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
//	  cert = new X509CertImpl(info);
//	  cert.sign(privkey, algorithm);
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

	public void generate(String dn, String csrFileName, String keyAlgorithm) {
		// TODO Auto-generated method stub
		
		try {
			keyAlgorithm="DSA";
			KeyPair keypair = generateKeyPair(keyAlgorithm);
			X509Certificate certificate = generateCertificate(dn, keypair, 30, "SHA1withDSA");
			pushToFile(certificate);
			
			System.out.println("successfull execution");
		} catch (GeneralSecurityException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	
	
	
}
