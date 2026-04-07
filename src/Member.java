import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.json.JSONObject;

public class Member extends CertificateHolder {
    public static Member initialize(String name, CertificateAuthority authoriser, char[] password)
            throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, IOException,
            KeyStoreException, UnrecoverableKeyException, NoSuchProviderException {
        Member mem = new Member();
        mem.name = name;
        try {
            if (new File("keystores/" + name + ".p12").exists()) {
                KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
                keyStore.load(new FileInputStream("keystores/" + name + ".p12"), password);
                PrivateKey privateKey = (PrivateKey) keyStore.getKey(name, password);
                Certificate cert = keyStore.getCertificate(name);

                mem.cert = (X509Certificate) cert;
                mem.keys = new KeyPair(cert.getPublicKey(), privateKey);

                return mem;
            }
        } catch (Exception e) {
            System.out.println("Certificate lost. Generating new certificate");
        }
        mem.keys = mem.generate();

        X500Name dn = new X500Name("CN=" + name + ", O=SecureGroup");

        Date from = new Date();
        Date to = new Date(from.getTime() + (365L * 24 * 60 * 60 * 1000));
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(authoriser.cert, serial, from, to,
                dn,
                mem.keys.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(authoriser.getPrivateKey());

        mem.cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

        PemWriter writer = new PemWriter(new FileWriter("keystores/" + name + ".pem"));
        writer.writeObject(new PemObject("CERTIFICATE", mem.cert.getEncoded()));
        writer.close();

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(name, (Key) mem.keys.getPrivate(), password,
                new Certificate[] { (Certificate) mem.cert });
        keyStore.store(new FileOutputStream("keystores/" + name + ".p12"), password);

        return mem;
    }

    public X509Certificate loadCertificate(CertificateAuthority ca, String filename)
            throws CertificateException, IOException {
        if (!filename.endsWith(".pem"))
            return null;
        X509Certificate cert;
        try (PemReader reader = new PemReader(new FileReader(filename))) {
            cert = new JcaX509CertificateConverter()
                    .getCertificate(new X509CertificateHolder(reader.readPemObject().getContent()));
        } catch (Exception e) {
            return null;
        }
        if (ca.checkBan(cert.getSerialNumber()))
            return null;
        else
            return cert;
    }

    public List<X509Certificate> loadAllCertificates(CertificateAuthority ca) throws CertificateException, IOException {
        List<X509Certificate> output = new ArrayList<>();
        File[] keystores = new File("keystores/").listFiles();
        if (keystores == null) {
            return output;
        }
        for (File file : keystores) {
            try {
                X509Certificate cert = loadCertificate(ca, file.getPath());
                if (cert != null)
                    output.add(cert);
            } catch (Exception e) {
                System.out.println("Exception loading certificates");
            }
        }
        return output;
    }

    public byte[] hashMessage(byte[] encryptedText, PrivateKey privateKey)
            throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(encryptedText);
        return sig.sign();
    }

    public JSONObject encryptMessage(CertificateAuthority ca, List<String> recipients, String message)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, SignatureException, CertificateException, IOException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = cipher.getIV();
        byte[] ciphertext = cipher.doFinal(message.getBytes());
        byte[] signature = hashMessage(ciphertext, getPrivateKey());
        List<X509Certificate> recipientCerts = new ArrayList<>();
        if (recipients.get(0).equals("All"))
            recipientCerts = loadAllCertificates(ca);
        else {
            if (!recipientCerts.contains(this.cert))
                recipientCerts.add(this.cert);
            for (String recipient : recipients) {
                X509Certificate cert = loadCertificate(ca, "keystores/" + recipient + ".pem");
                if (cert != null)
                    recipientCerts.add(cert);
            }
        }

        JSONObject recipientsJSON = new JSONObject();
        for (X509Certificate cert : recipientCerts) {
            PublicKey publicRSAKey = cert.getPublicKey();
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicRSAKey);
            byte[] encryptedKey = rsaCipher.doFinal(aesKey.getEncoded());
            String name = cert.getSubjectX500Principal().getName();
            recipientsJSON.put(name, Base64.getEncoder().encodeToString(encryptedKey));
        }

        JSONObject post = new JSONObject();
        post.put("sender", this.name);
        post.put("timestamp", new Date().toString());
        post.put("iv", Base64.getEncoder().encodeToString(iv));
        post.put("message", Base64.getEncoder().encodeToString(ciphertext));
        post.put("signature", Base64.getEncoder().encodeToString(signature));
        post.put("recipients", recipientsJSON);
        return post;
    }

    public String decryptMessage(JSONObject input, CertificateAuthority ca) throws CertificateException, IOException,
            NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        String sender = input.getString("sender");
        String timestamp = input.getString("timestamp");
        String messageB64 = input.getString("message");
        String ivB64 = input.getString("iv");
        String signatureB64 = input.getString("signature");
        JSONObject recipients = input.getJSONObject("recipients");
        String myKey = null;
        try {
            myKey = recipients.optString(this.cert.getSubjectX500Principal().getName(), null);
        } catch (NullPointerException e) {
            return "This message is encrypted and you do not have a certificate to decrypt it";
        }
        if (myKey == null)
            return "This message is encrypted and you do not have a certificate to decrypt it";

        PublicKey senderPublicKey = loadCertificate(ca, "keystores/" + sender + ".pem").getPublicKey();

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(senderPublicKey);
        sig.update(Base64.getDecoder().decode(messageB64));
        boolean valid = sig.verify(Base64.getDecoder().decode(signatureB64));
        if (!valid)
            return null;

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
        byte[] aesKeyBytes = rsaCipher.doFinal(Base64.getDecoder().decode(myKey));

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, Base64.getDecoder().decode(ivB64));
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
        String plaintext = new String(cipher.doFinal(Base64.getDecoder().decode(messageB64)));

        return sender + "@" + timestamp + ": " + plaintext;
    }
}
