import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CertificateHolder {
    KeyPair keys;
    X509Certificate cert;
    String name;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    protected KeyPair generate() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    protected PrivateKey getPrivateKey() {
        return keys.getPrivate();
    }

    protected PublicKey getPublicKey() {
        return keys.getPublic();
    }
}
