package mdcf;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

public class VerifyCertificate {

	@SuppressWarnings("unchecked")
	public boolean verify(X509Certificate x509certificateRoot,Collection collectionX509CertificateChain){
		System.out.println("Array Size: "+ collectionX509CertificateChain.size());
		int nSize = collectionX509CertificateChain.size();
	    X509Certificate [] arx509certificate = new X509Certificate [nSize];
	    collectionX509CertificateChain.toArray(arx509certificate);
	    checkRootCA(arx509certificate[0]);
	    
	    // Working down the chain, for every certificate in the chain,
	    // verify that the subject of the certificate is the issuer of the
	    // next certificate in the chain.
	    
	    Principal principalLast = null;
	    for (int i = 0; i < nSize; i++)
	    {
	      X509Certificate x509certificate = arx509certificate[i];
	      Principal principalIssuer = x509certificate.getIssuerDN();
	      Principal principalSubject = x509certificate.getSubjectDN();
	      if (principalLast != null)
	      {
	    	  System.out.println("principalIssuer: " + principalIssuer);
	        if (principalIssuer.equals(principalLast))
	        {
	          try
	          {
	            PublicKey publickey = arx509certificate[i - 1].getPublicKey();
	            arx509certificate[i].verify(publickey);
	            System.out.println("signature verificated");
	          }
	          catch (GeneralSecurityException generalsecurityexception)
	          {
	            System.out.println("signature verification failed");
	            return false;
	          }
	        }
	        else
	        {
	          System.out.println("subject/issuer verification failed");
	          return false;
	        }
	      }
	      principalLast = principalSubject;
	      System.out.println("principalLast: " + principalLast);
	    }
		
		return false;
	}
	
	public boolean checkRootCA(X509Certificate x509certificateRoot){
	
	    try
	    {
	      PublicKey publickey = x509certificateRoot.getPublicKey();
	      x509certificateRoot.verify(publickey);
	      System.out.println("Root Certificate Verified.");
	    }
	    catch (GeneralSecurityException generalsecurityexception)
	    {
	      System.out.println("signature verification failed");
	      return false;
	    }
	    return true;
	}
	
	public boolean checkValidity(X509Certificate x509certificate){
		// For every certificate in the chain, verify that the certificate
	    // is valid at the current time.
	    Date date = new Date();
	      try
	      {
	    	  x509certificate.checkValidity(date);
	      }
	      catch (GeneralSecurityException generalsecurityexception)
	      {
	        System.out.println("invalid date");
	        return false;
	      }
	    return true;
	  }
	
	public static void main(String[] args) throws FileNotFoundException, CertificateException {
		 
		//Read CA Certificate
		FileInputStream fis = new FileInputStream("CaCertificate.cer");
		 CertificateFactory cf = CertificateFactory.getInstance("X.509");
		 Collection c = cf.generateCertificates(fis);
		 Iterator i = c.iterator();
		 X509Certificate x509certificateRoot=null;
		 while (i.hasNext()) {
			 x509certificateRoot = (X509Certificate)i.next();
		 }
		 
		 //Read Manufacturer Certificate.
		fis = new FileInputStream("nellcor.cer");
		 cf = CertificateFactory.getInstance("X.509");
		 Collection c1 = cf.generateCertificates(fis);
		 i = c1.iterator();
		 X509Certificate manf=null;
		 while (i.hasNext()) {
		   manf = (X509Certificate)i.next();
		 }
		 
		 Collection<X509Certificate> collectionX509CertificateChain = new ArrayList<X509Certificate>();
		 collectionX509CertificateChain.add(x509certificateRoot);
		 collectionX509CertificateChain.add(manf);
		 
		 VerifyCertificate verifyCert = new VerifyCertificate();
		 verifyCert.verify(x509certificateRoot, collectionX509CertificateChain);
		 
	}
}
