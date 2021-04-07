package google_auth;

public class Login {
    public static void main(String[] args) {
        Manifest manifest = Manifest.GetManifest(false);
        GAuthAccount account = new GAuthAccount();
        account.name = "GateHub (k0tone@ukr.net)";
        account.secure = "ZZRFSVEC2ER4AHBI";
        manifest.SaveAccount(account, false, null);
        GAuthAccount account2 = new GAuthAccount();
        account2.name = "OpSkins (76561198275987975)";
        account2.secure = "U72RGODE43HGMOCR";
        manifest.SaveAccount(account2, false, null);
        GAuthAccount account4 = new GAuthAccount();
        account4.name = "OpSkins (76561198375116632)";
        account4.secure = "2V4E6OJBWV324EJK";
        manifest.SaveAccount(account4, false, null);
        GAuthAccount account3 = new GAuthAccount();
        account3.name = "BitSkins (k0tone)";
        account3.secure = "YKUKBC4QHD3QOUUV";
        manifest.SaveAccount(account3, false, null);
    }
}
