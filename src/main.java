import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.Arrays;

import org.json.JSONObject;

public class main {
    public static void main(String[] args) {
        char[] password = new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' }; // Hardcoded for testing's sake
        try {
            CertificateAuthority admin = CertificateAuthority.initialize("Admin", "keystores/CRL.json");
            new File("wall/wall.json").delete();
            Member kyara = Member.initialize("kyara", admin, password);
            Member taiga = Member.initialize("taiga", admin, password);
            Member zarya = Member.initialize("zarya", admin, password);
            BufferedWriter writer = new BufferedWriter(new FileWriter("wall/wall.json", true));
            writer.write(kyara.encryptMessage(admin, Arrays.asList("All"), "Test Message 1").toString());
            writer.newLine();
            writer.write(kyara.encryptMessage(admin, Arrays.asList("zarya"), "Test Message 2").toString());
            writer.newLine();
            writer.write(kyara.encryptMessage(admin, Arrays.asList("All"), "Test Message 3").toString());
            writer.newLine();
            writer.flush();
            writer.close();
            BufferedReader reader = new BufferedReader(new FileReader("wall/wall.json"));
            JSONObject message1 = new JSONObject(reader.readLine());
            JSONObject message2 = new JSONObject(reader.readLine());
            JSONObject message3 = new JSONObject(reader.readLine());
            System.out.println("Testing as kyara (sender)");
            System.out.println(kyara.decryptMessage(message1, admin));
            System.out.println(kyara.decryptMessage(message2, admin));
            System.out.println(kyara.decryptMessage(message3, admin));

            System.out.println("Testing as taiga (cannot view message 2 [Kyara-Zarya DM])");
            System.out.println(taiga.decryptMessage(message1, admin));
            System.out.println(taiga.decryptMessage(message2, admin));
            System.out.println(taiga.decryptMessage(message3, admin));

            System.out.println("Testing as zarya (banned from message 3)");
            System.out.println(zarya.decryptMessage(message1, admin));
            System.out.println(zarya.decryptMessage(message2, admin));
            admin.banCert(zarya);
            System.out.println(zarya.decryptMessage(message3, admin));
            reader.close();
        } catch (Exception e) {
            System.out.println(e);
            System.out.println("Bad");
            System.exit(1);
        }
    }
}