public class GPRunner {
    public static void main(String[] args) {
        try {
            long t0 = System.currentTimeMillis();
            // Pre-warm GPCrypto so SecureRandom entropy gathering happens BEFORE opening SCard transaction
            Class.forName("pro.javacard.gp.GPCrypto");
            long t1 = System.currentTimeMillis();
            System.err.println("[GPRunner] GPCrypto pre-warmed in " + (t1 - t0) + "ms");
            pro.javacard.gptool.GPTool.main(args);
        } catch (Throwable t) {
            t.printStackTrace();
            System.exit(1);
        }
    }
}
