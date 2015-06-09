package mdcf;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import sun.security.pkcs10.PKCS10;
import sun.security.x509.*;

public class CSRRequest {

	public  PKCS10 generatePKCS10(String keyAlgo, String keySize, X500Name x500Name, String outputFileName,String publicKeyName, String privateKeyName) throws Exception {
      
		// generate PKCS10 certificate request
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgo);
        String sigAlg;
        if(keyAlgo.equals("RSA")){
       sigAlg = "SHA1withRSA";
        }
        else{
        sigAlg = "SHA1withDSA";
        }
        
        // generate private key - use java.util.SecureRandom for entropy
        keyGen.initialize(1024, new SecureRandom());
        KeyPair keypair = keyGen.generateKeyPair();
        
        PublicKey publicKey = keypair.getPublic();
        PrivateKey privateKey = keypair.getPrivate();
        
        //write public and private key to a file.
        if(!publicKeyName.equals("") && !privateKeyName.equals("")){
        	 byte[] prkey = privateKey.getEncoded();
             FileOutputStream keyfos = new FileOutputStream(privateKeyName);
             keyfos.write(prkey);
             keyfos.close();
             byte[] pukey = publicKey.getEncoded();
             keyfos = new FileOutputStream(publicKeyName);
             keyfos.write(pukey);
             keyfos.close();
        }
        
        PKCS10 pkcs10 = new PKCS10(publicKey);
        
        Signature signature = Signature.getInstance(sigAlg);
        signature.initSign(privateKey);
    
        pkcs10.encodeAndSign(x500Name,signature);

        // PKCS10 request generated
        pkcs10.print(System.out);
       
        File csrFile=new File(outputFileName);
        FileOutputStream fos = new FileOutputStream(csrFile);
        PrintStream ps = new PrintStream(fos);
        pkcs10.print(ps);
        fos.close();
        
        return pkcs10;

    }
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
		//	generatePKCS10();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

}
