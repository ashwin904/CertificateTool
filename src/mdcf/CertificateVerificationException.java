package mdcf;

/**
 * This class wraps an exception that could be thrown during
 * the certificate verification process.
 * 
 * @author Ashwin Krishna
 */
public class CertificateVerificationException extends Exception {
    private static final long serialVersionUID = 1L;
 
    public CertificateVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
 
    public CertificateVerificationException(String message) {
        super(message);
    }
}
