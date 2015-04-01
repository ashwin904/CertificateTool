package mdcf;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import sun.misc.BASE64Encoder;
import sun.security.pkcs10.PKCS10;
import sun.security.provider.X509Factory;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import com.sun.xml.internal.messaging.saaj.util.ByteOutputStream;

public class HandleCSRRequest {

	private static final String SIGNATURE_ALGORITHM = "SHA1withDSA";
	private static final long VALIDITY_DAYS = 14L;


	public static byte[] sign(PKCS10 csr, X509CertImpl signerCert, PrivateKey signerPrivKey) throws CertificateException, IOException, InvalidKeyException, SignatureException {

	    /*
	     * The code below is partly taken from the KeyTool class in OpenJDK7.
	     */

	    X509CertInfo signerCertInfo = (X509CertInfo) signerCert.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);
	    X500Name issuer = (X500Name) signerCertInfo.get(X509CertInfo.SUBJECT + "." + CertificateSubjectName.DN_NAME);

	    /*
	     * Set the certificate's validity:
	     * From now and for VALIDITY_DAYS days 
	     */
	    Date firstDate = new Date();
	    Date lastDate = new Date();
	    lastDate.setTime(firstDate.getTime() + VALIDITY_DAYS * 1000L * 24L * 60L * 60L);
	    CertificateValidity interval = new CertificateValidity(firstDate, lastDate);

	    /*
	     * Initialize the signature object
	     */
	    Signature signature;
	    try {
	        signature = Signature.getInstance(SIGNATURE_ALGORITHM);
	    } catch (NoSuchAlgorithmException e) {
	        throw new RuntimeException(e);
	    }
	    signature.initSign(signerPrivKey);

	    /*
	     * Add the certificate information to a container object
	     */
	    X509CertInfo certInfo = new X509CertInfo();
	    certInfo.set(X509CertInfo.VALIDITY, interval);
	    certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new Random().nextInt() & 0x7fffffff));
	    certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
	    try {
	        certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get(SIGNATURE_ALGORITHM)));
	    } catch (NoSuchAlgorithmException e) {
	        throw new RuntimeException(e);
	    }
	    certInfo.set(X509CertInfo.ISSUER, issuer);
	    certInfo.set(X509CertInfo.KEY, new CertificateX509Key(csr.getSubjectPublicKeyInfo()));
	    certInfo.set(X509CertInfo.SUBJECT, csr.getSubjectName());

//	    /*
//	     * Add x509v3 extensions to the container
//	     */
//	    CertificateExtensions extensions = new CertificateExtensions();
//
//	    // Example extension.
//	    // See KeyTool source for more.
//	    boolean[] keyUsagePolicies = new boolean[9];
//	    keyUsagePolicies[0] = true; // Digital Signature
//	    keyUsagePolicies[2] = true; // Key encipherment
//	    KeyUsageExtension kue = new KeyUsageExtension(keyUsagePolicies);
//	    byte[] keyUsageValue = new DerValue(DerValue.tag_OctetString, kue.getExtensionValue()).toByteArray();
//	    extensions.set(KeyUsageExtension.NAME, new Extension(
//	            kue.getExtensionId(),
//	            true, // Critical
//	            keyUsageValue));


	    /*
	     * Create the certificate and sign it
	     */
	    X509CertImpl cert = new X509CertImpl(certInfo);
	    try {
	        cert.sign(signerPrivKey, SIGNATURE_ALGORITHM);
	    } catch (NoSuchAlgorithmException e) {
	        throw new RuntimeException(e);
	    } catch (NoSuchProviderException e) {
	        throw new RuntimeException(e);
	    }
	   
	    /*
	     * Return the signed certificate as PEM-encoded bytes
	     */
	    ByteOutputStream bos = new ByteOutputStream();
	    PrintStream out = new PrintStream(bos);
	    BASE64Encoder encoder = new BASE64Encoder();
	    out.println(X509Factory.BEGIN_CERT);
	    encoder.encodeBuffer(cert.getEncoded(), out);
	    out.println(X509Factory.END_CERT);
	    out.flush();
	    return bos.getBytes();
	}
	
	public boolean checkExistsPublicPrivateKey(String publicKey,String privateKey){
		File dir = new File(System.getProperty("user.dir"));
	    File[] dir_contents = dir.listFiles();
	    int a=0,b=0;
	    for(int i = 0; i<dir_contents.length;i++) {
	    	System.out.println(dir_contents[i].getName());
	        if(dir_contents[i].getName().equals(privateKey))
	            a=1;
	        if(dir_contents[i].getName().equals(publicKey))
	        	b=1;
	        if(a==1 && b==1){
	        	return true;
	    }
	}
	    return false;
	}
	
	public boolean checkExistsCertificate(String certificateName){
		File dir = new File(System.getProperty("user.dir"));
	    File[] dir_contents = dir.listFiles();
	    for(int i = 0; i<dir_contents.length;i++) {
	        if(dir_contents[i].getName().equals(certificateName))
	        	return true;
	    	}
	    return false;
	}
	
	
	public void createCAPublicPrivateKey(String Algorithm) throws NoSuchAlgorithmException, IOException
	{
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(Algorithm);
		keyGen.initialize(1024, new SecureRandom());
        KeyPair keypair = keyGen.generateKeyPair();
        PublicKey publicKey=keypair.getPublic();
        PrivateKey privateKey = keypair.getPrivate();
        byte[] pukey = publicKey.getEncoded();
        FileOutputStream keyfos = new FileOutputStream("CaPublicKey.pem");
        keyfos.write(pukey);
        keyfos.close();
        byte[] prkey = privateKey.getEncoded();
        keyfos = new FileOutputStream("CaPrivateKey.pem");
        keyfos.write(prkey);
        keyfos.close();
	}
	
	public void createCertificateFromCSR(PKCS10 pkcs10,X509CertImpl certInfo,String key, String certificateName){
	
		try {
			FileInputStream keyfis = new FileInputStream(key);
			byte[] encKey = new byte[keyfis.available()];  
			keyfis.read(encKey);
			keyfis.close();
			PKCS8EncodedKeySpec pubKeySpec = new PKCS8EncodedKeySpec(encKey);
			KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
			PrivateKey privateKey = keyFactory.generatePrivate(pubKeySpec);
		
			byte[] certbyte=sign(pkcs10,certInfo,privateKey);
			File file = new File(certificateName + ".cer");
			FileOutputStream os = new FileOutputStream(file);
			os.write(certbyte);
			os.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@SuppressWarnings("rawtypes")
	public void handleRequest(PKCS10 pkcs10, String certificateName, String signer) throws Exception{
		
		
		/**Check if signer's private & public key exits and also respective certificates.
		and create CA's if it does not exits **/
		
		if(signer.equals("CA")){
			boolean keyFlag = checkExistsPublicPrivateKey("CaPublicKey.pem","CaPrivateKey.pem");
			if(!keyFlag) createCAPublicPrivateKey("DSA");
			boolean certFlag = checkExistsCertificate("CACertificate.cer");
			if(!certFlag) {
				CreateX509Certificate createCertificate=new CreateX509Certificate();
				String dn = "CN=CertificateAuthorityName, L=Manhattan, ST=KS, C=US";
				X509CertImpl certInfo=(X509CertImpl) createCertificate.generateCertificate(dn,30,"SHA1withDSA");
				FileOutputStream out = new FileOutputStream("CACertificate.cer");
				BASE64Encoder encoder = new BASE64Encoder();
				out.write(X509Factory.BEGIN_CERT.getBytes());
				out.write('\n');
			    encoder.encodeBuffer(certInfo.getEncoded(), out);
			    out.write(X509Factory.END_CERT.getBytes());
			    createCertificateFromCSR(pkcs10,certInfo,"CaPrivateKey.pem",certificateName);
			}
			// reading CA's certificate if it already exits.
			else{
				System.out.println("Reading CA's certificate");
				FileInputStream fis = new FileInputStream("CaCertificate.cer");
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				Collection c = cf.generateCertificates(fis);
				Iterator i = c.iterator();
				 Certificate cert = null;
				while (i.hasNext()) {
				    cert = (Certificate)i.next();
				 }
				if(cert==null) throw new Exception("Error while trying to read CA's Certificate in " + this.getClass());
				else{
					X509CertImpl certInfo=(X509CertImpl) cert;
					createCertificateFromCSR(pkcs10,certInfo,"CaPrivateKey.pem",certificateName);
				}
			}
			
		}
		else {
			boolean keyFlag = checkExistsPublicPrivateKey("ManfPublicKey.pem","ManfPrivateKey.pem");
			if(!keyFlag) throw new Exception("Manufacturer Public & Private key not found.");
			boolean certFlag = checkExistsCertificate(signer);
			if(!certFlag) throw new Exception("Manufacturer Certificate Not Found.");
			else{
				 KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
				    keyGen.initialize(1024, new SecureRandom());
			        KeyPair keypair = keyGen.generateKeyPair();
			        
			        PublicKey publicKey = keypair.getPublic();
			        PrivateKey privateKey = keypair.getPrivate();
			        
			        //write public and private key to a file.
			        
			        	 byte[] prkey = privateKey.getEncoded();
			             FileOutputStream keyfos = new FileOutputStream("DeviceModelPK.pem");
			             keyfos.write(prkey);
			             keyfos.close();
			             byte[] pukey = publicKey.getEncoded();
			             keyfos = new FileOutputStream("DeviceModelPubK.pem");
			             keyfos.write(pukey);
			             keyfos.close();
			        
				System.out.println("Reading Manufacturer's certificate");
				FileInputStream fis = new FileInputStream(signer);
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				Collection c = cf.generateCertificates(fis);
				Iterator i = c.iterator();
				 Certificate cert = null;
				while (i.hasNext()) {
				    cert = (Certificate)i.next();
				 }
				if(cert==null) throw new Exception("Error while trying to read Manufacturer's Certificate "+ signer +" in " + this.getClass());
				else{
					X509CertImpl certInfo=(X509CertImpl) cert;
					createCertificateFromCSR(pkcs10,certInfo,"ManfPrivateKey.pem",certificateName);
				}
			}
			
		}
	}
	
	public void handleDeviceModel(String ca, String manf, String devicecsr) throws FileNotFoundException, CertificateException{
		
		FileInputStream fis = new FileInputStream(ca);
		 CertificateFactory cf = CertificateFactory.getInstance("X.509");
		 Collection c = cf.generateCertificates(fis);
		 Iterator i = c.iterator();
		 while (i.hasNext()) {
		    X509Certificate cert = (X509Certificate)i.next();
		 }
		 
		 fis = new FileInputStream(manf);
		 cf = CertificateFactory.getInstance("X.509");
		 Collection c1 = cf.generateCertificates(fis);
		 Iterator i1 = c1.iterator();
		 while (i1.hasNext()) {
		    X509Certificate cert = (X509Certificate)i1.next();
		 }
		 
		
	}
	
	
//	public static void main(String[]args) throws Exception{
//        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
//        // generate private key - use java.util.SecureRandom for entropy
//        keyGen.initialize(1024, new SecureRandom());
//        KeyPair keypair = keyGen.generateKeyPair();
//        PublicKey publicKey=keypair.getPublic();
//        PrivateKey privateKey = keypair.getPrivate();
//		CreateX509Certificate demo=new CreateX509Certificate();
//		X509CertImpl certInfo=(X509CertImpl) demo.generate();
//		PKCS10 pkcs10=CSRRequest.generatePKCS10();
//		byte[] certbyte=sign(pkcs10,certInfo,privateKey);
//		File file = new File("prams.pem");
//	    FileOutputStream os = new FileOutputStream(file);
//	    os.write(certbyte);
//	    os.close();
//	}
}
