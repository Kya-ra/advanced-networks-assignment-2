import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import java.math.BigInteger;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class CertificateAuthority extends CertificateHolder {
    Set<BigInteger> revoked;
    String banFilename;

    public static CertificateAuthority initialize(String name, String filename)
            throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, IOException {
        CertificateAuthority ca = new CertificateAuthority();
        ca.name = name;
        ca.keys = ca.generate();
        ca.revoked = new HashSet<BigInteger>();
        ca.banFilename = filename;

        ca.loadBans();

        X500Name dn = new X500Name("CN=" + name + ", O=SecureGroup");

        Date from = new Date();
        Date to = new Date(from.getTime() + (365L * 24 * 60 * 60 * 1000));
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dn, serial, from, to, dn,
                ca.keys.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(ca.keys.getPrivate());

        ca.cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

        return ca;
    }

    public void loadBans() {
        try (BufferedReader reader = new BufferedReader(new FileReader(banFilename))) {
            String line;

            while ((line = reader.readLine()) != null) {
                line = line.trim();

                if (!line.isEmpty()) {
                    if (!line.isEmpty()) {
                        this.revoked.add(new BigInteger(line));
                    }
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public Boolean checkBan(BigInteger serial) {
        return this.revoked.contains(serial);
    }

    public void banCert(Member member) {
        X509Certificate cert = member.cert;
        member.cert = null;
        this.revoked.add(cert.getSerialNumber());
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(banFilename, true))) {
            writer.write(cert.getSerialNumber().toString());
            writer.newLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
