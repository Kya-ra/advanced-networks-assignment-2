import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONObject;

//This testing harness was AI generated from my original testing scenario for the sake of demonstration

public class main {

    static Map<String, Member> members = new HashMap<>();
    static CertificateAuthority admin;
    static char[] password = new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };

    public static void main(String[] args) {

        try {
            admin = CertificateAuthority.initialize("Admin", "keystores/CRL.json");
        } catch (Exception e) {
            System.err.println("[FATAL] Could not initialise CA: " + e.getMessage());
            System.exit(1);
        }

        new File("wall").mkdirs();

        BufferedReader console = new BufferedReader(new InputStreamReader(System.in));
        printHelp();

        while (true) {
            System.out.print("\n> ");
            String line;
            try {
                line = console.readLine();
            } catch (IOException e) {
                System.err.println("Error reading input: " + e.getMessage());
                break;
            }

            if (line == null || line.equalsIgnoreCase("exit") || line.equalsIgnoreCase("quit")) {
                System.out.println("Bye.");
                break;
            }

            line = line.trim();
            if (line.isEmpty())
                continue;

            String[] tokens = tokenise(line);
            if (tokens.length == 0)
                continue;

            String cmd = tokens[0].toLowerCase();

            try {
                switch (cmd) {
                    case "create": {
                        if (tokens.length < 2) {
                            System.out.println("Usage: create <username>");
                            break;
                        }
                        String username = tokens[1];
                        if (members.containsKey(username)) {
                            break;
                        }
                        Member m = Member.initialize(username, admin, password);
                        members.put(username, m);
                        break;
                    }

                    case "send": {
                        if (tokens.length < 4) {
                            System.out.println("Usage: send <sender> <recipient1[,recipient2,...]> \"<message>\"");
                            break;
                        }
                        Member sender = resolveMember(tokens[1]);
                        if (sender == null)
                            break;

                        List<String> recipients = Arrays.asList(tokens[2].split(","));
                        String message = tokens[3];

                        BufferedWriter writer = new BufferedWriter(new FileWriter("wall/wall.json", true));
                        writer.write(sender.encryptMessage(admin, recipients, message).toString());
                        writer.newLine();
                        writer.close();
                        break;
                    }

                    case "read": {
                        if (tokens.length < 2) {
                            System.out.println("Usage: read <username>");
                            break;
                        }
                        Member reader = resolveMember(tokens[1]);
                        if (reader == null)
                            break;

                        File wall = new File("wall/wall.json");
                        if (!wall.exists() || wall.length() == 0) {
                            break;
                        }

                        BufferedReader br = new BufferedReader(new FileReader(wall));
                        String rawLine;
                        int index = 0;
                        while ((rawLine = br.readLine()) != null) {
                            if (rawLine.trim().isEmpty())
                                continue;
                            index++;
                            try {
                                org.json.JSONObject msg = new org.json.JSONObject(rawLine);
                                String decrypted = reader.decryptMessage(msg, admin);
                                System.out.println(
                                        "  [" + index + "] " + (decrypted != null ? decrypted : "<not accessible>"));
                            } catch (Exception e) {
                                System.out.println("  [" + index + "] <error decrypting: " + e.getMessage() + ">");
                            }
                        }
                        br.close();
                        break;
                    }

                    case "ban": {
                        if (tokens.length < 2) {
                            System.out.println("Usage: ban <username>");
                            break;
                        }
                        Member target = resolveMember(tokens[1]);
                        if (target == null)
                            break;
                        admin.banCert(target);
                        break;
                    }

                    case "clear": {
                        new File("wall/wall.json").delete();
                        break;
                    }

                    case "reset": {
                        new File("wall/wall.json").delete();
                        for (String name : members.keySet()) {
                            new File("keystores/" + name + ".p12").delete();
                        }
                        members.clear();
                        admin = CertificateAuthority.initialize("Admin", "keystores/CRL.json");
                        break;
                    }

                    case "list": {
                        if (members.isEmpty()) {
                            System.out.println("No members in this session.");
                        } else {
                            System.out.println("Members: " + String.join(", ", members.keySet()));
                        }
                        break;
                    }

                    case "scenario": {
                        runScenario();
                        break;
                    }

                    case "help": {
                        printHelp();
                        break;
                    }

                    default:
                        System.out.println("Unknown command '" + cmd + "'. Type 'help' for usage.");
                }

            } catch (Exception e) {
                System.err.println("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
    }

    private static Member resolveMember(String name) {
        Member m = members.get(name);
        if (m == null) {
            System.out.println("[ERROR] Unknown member '" + name + "'. Did you run 'create " + name + "'?");
        }
        return m;
    }

    private static String[] tokenise(String line) {
        List<String> tokens = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ' ' && !inQuotes) {
                if (current.length() > 0) {
                    tokens.add(current.toString());
                    current.setLength(0);
                }
            } else {
                current.append(c);
            }
        }
        if (current.length() > 0)
            tokens.add(current.toString());
        return tokens.toArray(new String[0]);
    }

    private static void printHelp() {
        System.out.println();
        System.out.println("Commands:");
        System.out.println("  create <username>                           Create and register a new member");
        System.out.println("  send <sender> <recipient[,recipient]> \"msg\" Send an encrypted message");
        System.out.println("                                               Use 'All' as recipient for broadcast");
        System.out.println("  read <username>                             Print all wall messages visible to user");
        System.out.println("  ban <username>                              Revoke a member's certificate");
        System.out.println("  list                                        List all members in this session");
        System.out.println("  clear                                       Delete all messages from the wall");
        System.out.println("  reset                                       Clear wall + members, re-init CA");
        System.out.println("  scenario                                    Run the built-in smoke-test scenario");
        System.out.println("  help                                        Show this help");
        System.out.println("  exit / quit                                 Exit the harness");
    }

    private static void runScenario() throws Exception {
        new File("wall/wall.json").delete();

        Member kyara = Member.initialize("kyara", admin, password);
        Member taiga = Member.initialize("taiga", admin, password);
        Member zarya = Member.initialize("zarya", admin, password);
        members.put("kyara", kyara);
        members.put("taiga", taiga);
        members.put("zarya", zarya);

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
    }
}