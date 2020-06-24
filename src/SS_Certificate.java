/**
 * @Autors: Karlis Zars
 * SS_Certificate klase izmantojot Bouncycastle API generee sertifikatu pec X.509 standarta 
 */
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.io.File;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import java.math.BigInteger;
import java.io.FileOutputStream;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.KeyStore;
import java.util.Date;

public class SS_Certificate {
    private static final int bitCount = 2048;
    private static final String param = "CN=cn, O=o, L=L, ST=il, C= c";
    private static final String alias = "KarlisZars";
    private static final String algo = "RSA";
    private static final String filename = "key.txt";

    public static void main(String[] args) throws Exception {
    	SS_Certificate signedCertificate = new SS_Certificate();
        signedCertificate.createCertificate(); 
    }
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    private void saveCert(X509Certificate cert, PrivateKey key) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");    
        keyStore.load(null, null);
        keyStore.setKeyEntry(alias, key, "KarlisZars".toCharArray(),  new java.security.cert.Certificate[]{cert});
        File file = new File(".", filename);
        keyStore.store( new FileOutputStream(file), "KarlisZars".toCharArray() );
    }

    @SuppressWarnings("deprecation")
	private X509Certificate createCertificate() throws Exception{
        X509Certificate cert = null;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algo);
        keyPairGenerator.initialize(bitCount, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        // Sertifikata genereesana
        X509V3CertificateGenerator v3CertGen =  new X509V3CertificateGenerator();
        v3CertGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        v3CertGen.setIssuerDN(new X509Principal(param));
        v3CertGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24));
        v3CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365*10)));
        v3CertGen.setSubjectDN(new X509Principal(param));
        v3CertGen.setPublicKey(keyPair.getPublic());
        v3CertGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        cert = v3CertGen.generateX509Certificate(keyPair.getPrivate());
        saveCert(cert,keyPair.getPrivate());
        return cert;
    }

}
