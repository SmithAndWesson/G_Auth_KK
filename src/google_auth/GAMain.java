package google_auth;

import java.util.List;

public class GAMain {
    public static GAuthAccount currentAccount = null;
    private static List<GAuthAccount> allAccounts = null;
    private static Manifest manifest;

    private static void loadAccountsList() {
        currentAccount = null;
        allAccounts = manifest.GetAllAccounts("");
    }

    private static void loadAccountInfo() {
        GAuth gAuth = new GAuth();
        if (currentAccount != null) {
            String text = gAuth.generate(currentAccount.secure);
            System.out.println(text + "\t" + currentAccount.name);
        }
    }

    public static void main(String[] args) {
        manifest = Manifest.GetManifest(false);
        loadAccountsList();
        currentAccount = allAccounts.get(2);
        loadAccountInfo();
    }
}
