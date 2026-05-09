import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
 
public class Secureexchange {
 
    
    static final long P = 199;   
    static final long G = 127;   
 
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
 
        printBanner();
 
       
        System.out.print("  Enter Private Key for User A : ");
        long privA = sc.nextLong();
 
        System.out.print("  Enter Private Key for User B : ");
        long privB = sc.nextLong();
        sc.nextLine(); 
 
        System.out.print("  Enter Message                : ");
        String message = sc.nextLine();
 
        
        printSectionHeader("STEP 1", "DIFFIE-HELLMAN KEY EXCHANGE");
 
        long pubA = modpow(G, privA, P);   
        long pubB = modpow(G, privB, P);   
 
        long sharedA = modpow(pubB, privA, P);  
        long sharedB = modpow(pubA, privB, P); 
 
        System.out.println("  Prime  (p)          = " + P);
        System.out.println("  Generator  (g)      = " + G);
        System.out.println();
        System.out.printf("  User A Private Key  = %d%n", privA);
        System.out.printf("  User A Public Value = g^%d mod %d = %d%n", privA, P, pubA);
        System.out.println();
        System.out.printf("  User B Private Key  = %d%n", privB);
        System.out.printf("  User B Public Value = g^%d mod %d = %d%n", privB, P, pubB);
        System.out.println();
        System.out.printf("  Shared Key (A side) = %d^%d mod %d = %d%n", pubB, privA, P, sharedA);
        System.out.printf("  Shared Key (B side) = %d^%d mod %d = %d%n", pubA, privB, P, sharedB);
        System.out.println();
 
        if (sharedA == sharedB) {
            System.out.println("  ✔  Keys Match! Shared Key = " + sharedA);
        } else {
            System.out.println("  ✘  Keys do NOT match. Check your inputs.");
            return;
        }
 
        
        printSectionHeader("STEP 2", "BUILDING THE 128-BIT AES KEY");
 
        String aesKey = buildAesKey(sharedA);
        int digits = String.valueOf(sharedA).length();
 
        System.out.println("  Shared Key          = " + sharedA);
        System.out.println("  Digit Count         = " + digits);
 
        if (digits == 1) {
            System.out.println("  Rule Applied        = Single digit → alternate with 'C'");
        } else if (digits == 2) {
            System.out.println("  Rule Applied        = Two digits  → alternate with 'DD'");
        } else {
            System.out.println("  Rule Applied        = Three digits → use 'F' as separator");
        }
 
        System.out.println();
        System.out.println("  AES-128 Key (16 chars) = [ " + aesKey + " ]");
        System.out.println("  AES-128 Key (Hex)      = " + toHex(aesKey));
 
        
        printSectionHeader("STEP 3", "MESSAGE CHUNKING & ENCRYPTION  (User A → User B)");
 
        System.out.println("  Original Message    = \"" + message + "\"");
        System.out.println("  Message Length      = " + message.length() + " characters");
        System.out.println();
 
        List<String> chunks = chunkMessage(message);
        List<String> encryptedChunks = new ArrayList<>();
 
        System.out.println("  ┌──────┬──────────────────┬──────────────────────────────────────────────────┐");
        System.out.println("  │  #   │  Plaintext Block │  Encrypted Block (Hex)                           │");
        System.out.println("  ├──────┼──────────────────┼──────────────────────────────────────────────────┤");
 
        for (int i = 0; i < chunks.size(); i++) {
            String plain = chunks.get(i);
            String enc   = xorBlock(plain, aesKey);
            encryptedChunks.add(enc);
            System.out.printf("  │  %-3d │  %-16s│  %-48s│%n",
                    i + 1,
                    plain.replace("\n", "\\n"),
                    toHex(enc));
        }
 
        System.out.println("  └──────┴──────────────────┴──────────────────────────────────────────────────┘");
 
      
        StringBuilder encFull = new StringBuilder();
        for (String e : encryptedChunks) encFull.append(e);
        String transmitted = encFull.toString();
 
        System.out.println();
        System.out.println("  Transmitted (Hex)   = " + toHex(transmitted));
 
        
        printSectionHeader("STEP 4", "DECRYPTION  (User B receives)");
 
        
        List<String> rxChunks = new ArrayList<>();
        for (int i = 0; i < transmitted.length(); i += 16)
            rxChunks.add(transmitted.substring(i, Math.min(i + 16, transmitted.length())));
 
        System.out.println("  ┌──────┬──────────────────────────────────────────────────┬──────────────────┐");
        System.out.println("  │  #   │  Received Block (Hex)                            │  Decrypted Block │");
        System.out.println("  ├──────┼──────────────────────────────────────────────────┼──────────────────┤");
 
        StringBuilder decFull = new StringBuilder();
        for (int i = 0; i < rxChunks.size(); i++) {
            String rx  = rxChunks.get(i);
            String dec = xorBlock(rx, aesKey);
            decFull.append(dec);
            System.out.printf("  │  %-3d │  %-48s│  %-16s│%n",
                    i + 1,
                    toHex(rx),
                    dec.replace("\n", "\\n"));
        }
 
        System.out.println("  └──────┴──────────────────────────────────────────────────┴──────────────────┘");
 
       
        String finalMessage = decFull.toString().replaceAll("@+$", "");
 
        
        System.out.println();
        System.out.println("  ╔══════════════════════════════════════════════════════════════╗");
        System.out.println("  ║                     DECRYPTED MESSAGE                        ║");
        System.out.printf( "  ║  %-60s║%n", "\"" + finalMessage + "\"");
        System.out.println("  ╚══════════════════════════════════════════════════════════════╝");
        System.out.println();
 
        sc.close();
    }
 
    
    static long modpow(long base, long exp, long mod) {
        long result = 1;
        base = base % mod;
        while (exp > 0) {
            if ((exp % 2) == 1)          
                result = result * base % mod;
            exp = exp / 2;
            base = base * base % mod;
        }
        return result;
    }
 
    
    static String buildAesKey(long shared) {
        String s = String.valueOf(shared);
        StringBuilder key = new StringBuilder();
 
        if (s.length() == 1) {
            while (key.length() < 16) key.append(s).append("C");
        } else if (s.length() == 2) {
            while (key.length() < 16) key.append(s).append("DD");
        } else {
            while (key.length() < 20) key.append(s).append("F");
        }
 
        return key.toString().substring(0, 16);
    }
 
    
    static List<String> chunkMessage(String msg) {
        List<String> chunks = new ArrayList<>();
        for (int i = 0; i < msg.length(); i += 16) {
            String chunk = msg.substring(i, Math.min(i + 16, msg.length()));
            // Pad with '@' (ASCII 64 / 01000000) if needed
            while (chunk.length() < 16) chunk += "@";
            chunks.add(chunk);
        }
        return chunks;
    }
 
    
    static String xorBlock(String block, String key) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < block.length(); i++) {
            result.append((char)(block.charAt(i) ^ key.charAt(i % key.length())));
        }
        return result.toString();
    }
 
    
    static String toHex(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            sb.append(String.format("%02X ", (int) c));
        }
        return sb.toString().trim();
    }
 
   
    static void printBanner() {
        System.out.println();
        System.out.println("  ╔══════════════════════════════════════════════════════════════╗");
        System.out.println("  ║         SECURE INFORMATION EXCHANGE PROGRAM                  ║");
        System.out.println("  ║              Diffie-Hellman  +  AES-128                      ║");
        System.out.println("  ╚══════════════════════════════════════════════════════════════╝");
        System.out.println();
    }
 
    static void printSectionHeader(String step, String title) {
        System.out.println();
        System.out.println("  ──────────────────────────────────────────────────────────────");
        System.out.println("  " + step + "  │  " + title);
        System.out.println("  ──────────────────────────────────────────────────────────────");
        System.out.println();
    }
}