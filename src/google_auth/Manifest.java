package google_auth;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class Manifest implements Serializable {
    //private static final long serialVersionUID = 8740264612621413542L;

    //[JsonProperty("first_run")]
    public boolean FirstRun = true;

    //[JsonProperty("entries")]
    public List<ManifestEntry> Entries;

    private static Manifest _manifest;

    public static String GetExecutableDir()
    {
        return System.getProperty("user.dir");
    }

    public static Manifest GetManifest(boolean forceLoad)
    {
        // Check if already staticly loaded
        if (_manifest != null && !forceLoad) {
            return _manifest;
        }

        // Find config dir and manifest file
        String maDir = Manifest.GetExecutableDir() + "/src/google_auth/maFiles/";
        String maFile = maDir + "manifest.json";

        File maDirPath = new File(maDir);
        File maFilePath = new File(maFile);

        // If there's no config dir, create it
        if(!maDirPath.exists()) {
            _manifest = _generateNewManifest(false);
            return _manifest;
        }

        // If there's no manifest, create it
        if (!maFilePath.exists()) {
            _manifest = _generateNewManifest(true);
            return _manifest;
        }

        try {
            FileInputStream fiStream = new FileInputStream(maFile);
            ObjectInputStream objectStream = new ObjectInputStream(fiStream);

            Manifest _manifest = (Manifest) objectStream.readObject();

            fiStream.close();
            objectStream.close();

            if (_manifest.Entries.size() == 0) {
                _manifest.Save();
            }

            _manifest.RecomputeExistingEntries();
            _manifest.RecomputeOutsideEntries();

            return _manifest;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return null;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static Manifest _generateNewManifest(boolean scanDir)
    {
        // No directory means no manifest file anyways.
        Manifest newManifest = new Manifest();
        newManifest.Entries = new ArrayList<ManifestEntry>();
        newManifest.FirstRun = true;

        // Take a pre-manifest version and generate a manifest for it.
        if (scanDir)
        {
            String maDir = Manifest.GetExecutableDir() + "/src/google_auth/maFiles/";
            File maDirPath = new File(maDir);

            if (maDirPath.exists()) {
                File[] files = maDirPath.listFiles();
                if (files != null) {
                    for (File file : files) {
                        if (!(file.getPath().lastIndexOf(".maFile") >= 0))
                            continue;
                        try {
                            FileInputStream fiStream = new FileInputStream(file.getPath());
                            ObjectInputStream objectStream = new ObjectInputStream(fiStream);
                            GAuthAccount account = (GAuthAccount) objectStream.readObject();

                            ManifestEntry newEntry = new ManifestEntry();
                            newEntry.Filename = file.getName();
                            newEntry.Secure = account.secure;

                            newManifest.Entries.add(newEntry);

                            fiStream.close();
                            objectStream.close();
                        } catch (FileNotFoundException e) {
                            e.printStackTrace();
                        } catch (IOException e) {
                            e.printStackTrace();
                        } catch (ClassNotFoundException e) {
                            e.printStackTrace();
                        }
                    }
                }

                if (newManifest.Entries.size() > 0)
                {
                    newManifest.Save();
                }
            }
        }

        if (newManifest.Save())
        {
            return newManifest;
        }

        return null;
    }

    private void RecomputeExistingEntries()
    {
        List<ManifestEntry> newEntries = new ArrayList<ManifestEntry>();
        String maDir = Manifest.GetExecutableDir() + "/src/google_auth/maFiles/";

        for (ManifestEntry entry : this.Entries)
        {
            String filename = maDir + entry.Filename;
            File f = new File(filename);
            if (f.exists()) {
                newEntries.add(entry);
            }
        }

        this.Entries = newEntries;
    }

    private void RecomputeOutsideEntries()
    {
        String maDir = Manifest.GetExecutableDir() + "/src/google_auth/maFiles/";
        File maDirPath = new File(maDir);

        if (maDirPath.exists()) {
            File[] files = maDirPath.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (!(file.getPath().lastIndexOf(".maFile") >= 0))
                        continue;
                    try {
                        FileInputStream fiStream = new FileInputStream(file.getPath());
                        ObjectInputStream objectStream = new ObjectInputStream(fiStream);
                        GAuthAccount account = (GAuthAccount) objectStream.readObject();

                        ManifestEntry newEntry = new ManifestEntry();
                        newEntry.Filename = file.getName();
                        newEntry.Secure = account.secure;

                        if (!this.Entries.contains(newEntry)) {
                            this.Entries.add(newEntry);
                        }

                        fiStream.close();
                        objectStream.close();
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    } catch (ClassNotFoundException e) {
                        e.printStackTrace();
                    }
                }
            }

            if (this.Entries.size() > 0) {
                this.Save();
            }
        }
    }

    public boolean RemoveAccount(GAuthAccount account, boolean deleteMaFile) {
        ManifestEntry entry = null;
        for (ManifestEntry e : this.Entries) {
            if (e.Secure.equals(account.secure)) {
                entry = e;
                break;
            }
        }

        if (entry == null) return true; // If something never existed, did you do what they asked?

        String maDir = Manifest.GetExecutableDir() + "/src/google_auth/maFiles/";
        String filename = maDir + entry.Filename;
        this.Entries.remove(entry);

        if (this.Save() && deleteMaFile) {
            try {
                Files.delete(Paths.get(filename));
            } catch (IOException e) {
                e.printStackTrace();
            }
            return true;
        }

        return false;
    }

    public boolean SaveAccount(GAuthAccount account, boolean encrypt, String passKey)
    {
        if (encrypt && (passKey.isEmpty() || passKey == null)) return false;

        String maDir = Manifest.GetExecutableDir() + "/src/google_auth/maFiles/";
        String filename = String.valueOf(account.name) + ".maFile";

        ManifestEntry newEntry = new ManifestEntry();
        newEntry.Secure = account.secure;
        newEntry.Filename = filename;

        boolean foundExistingEntry = false;
        for (int i = 0; i < this.Entries.size(); i++) {
            if (this.Entries.get(i).Secure.equals(account.secure)) {
                this.Entries.set(i, newEntry);
                foundExistingEntry = true;
                break;
            }
        }

        if (!foundExistingEntry) {
            this.Entries.add(newEntry);
        }

        if (!this.Save()) {
            return false;
        }

        try {
            FileOutputStream fileOutput = new FileOutputStream(maDir + filename);
            ObjectOutputStream outputStream = new ObjectOutputStream(fileOutput);

            outputStream.writeObject(account);

            fileOutput.close();
            outputStream.close();

            return true;
        } catch (FileNotFoundException e) {
            return false;
        } catch (IOException e) {
            return false;
        }
    }

    public boolean Save() {
        String maDir = Manifest.GetExecutableDir() + "/src/google_auth/maFiles/";
        String filename = maDir + "manifest.json";

        File maDirPath = new File(maDir);

        if (!maDirPath.exists()) {
            maDirPath.mkdir();
        }

        try {
            FileOutputStream fileOutput = new FileOutputStream(filename);
            ObjectOutputStream outputStream = new ObjectOutputStream(fileOutput);

            outputStream.writeObject(this);

            fileOutput.close();
            outputStream.close();

            return true;
        } catch (FileNotFoundException e) {
            return false;
        } catch (IOException e) {
            return false;
        }
    }

    public static class ManifestEntry implements Serializable {
        private static final long serialVersionUID = 4807116196338011157L;

        public String Filename;
        public String Secure;

        @Override
        public boolean equals(Object obj) {
            ManifestEntry manifestEntry = (ManifestEntry)obj;
            String Secure = String.valueOf(this.Secure);
            String objSecure = String.valueOf(manifestEntry.Secure);
            return Secure.equals(objSecure);
        }
    }

    public List<GAuthAccount> GetAllAccounts(String passKey)
    {
        List<GAuthAccount> accounts = new ArrayList<GAuthAccount>();
        if (passKey == null) {
            accounts.add(new GAuthAccount());
            return accounts;
        }
        String maDir = Manifest.GetExecutableDir() + "/src/google_auth/maFiles/";

        for (ManifestEntry entry : this.Entries) {
            try {
                FileInputStream fiStream = new FileInputStream(maDir + entry.Filename);
                ObjectInputStream objectStream = new ObjectInputStream(fiStream);
                GAuthAccount account = (GAuthAccount) objectStream.readObject();

                if (account == null) continue;
                accounts.add(account);

                fiStream.close();
                objectStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        }

        return accounts;
    }
}
