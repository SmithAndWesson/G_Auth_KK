package google_auth;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

public class GAForm extends JFrame {
    public static GAuthAccount currentAccount = null;
    public static List<GAuthAccount> allAccounts = null;
    private static Manifest manifest;
    private static GAuth gAuth = new GAuth();

    private JPanel rootPanel;
    private JProgressBar progressBar1;
    private JTextField currentCode;
    private JButton copyButton;
    private JList listAccounts;
    private JButton setupNewAccountButton;
    private JButton removeAccountButton;

    private Icon ico;

    public GAForm() {
        setContentPane(rootPanel);
        setTitle("Google Authenticator v.1.0");
        pack();
        Dimension screen = Toolkit.getDefaultToolkit().getScreenSize();
        setLocationRelativeTo(null);

        ImageIcon img = new ImageIcon(new ImageIcon(System.getProperty("user.dir") + "\\src\\google_auth\\ico.png").getImage().getScaledInstance(440, 440, Image.SCALE_DEFAULT));
        setIconImage(img.getImage());
        ico = new ImageIcon(img.getImage());

        progressBar1.setStringPainted(true);
        progressBar1.setMinimum(0);
        progressBar1.setMaximum(30);
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

        // создаем слушателей для элементов формы
        createListeners();
        // считываем с диска файлы с данными от аккаунтов
        manifest = Manifest.GetManifest(false);
        // получаем список аккаунтов и выбираем первый из списка
        loadAccountsList();
        // подключаем таймер для обновления Google Authenticator Code
        timerSteamGuard_Tick();
    }

    public void createListeners() {
        listAccounts.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                for (int i = 0; i < allAccounts.size(); i++) {
                    // Check if index is out of bounds first
                    if (i < 0 || listAccounts.getSelectedIndex() < 0)
                        continue;

                    GAuthAccount account = allAccounts.get(i);
                    if (account.name.equals(listAccounts.getModel().getElementAt(listAccounts.getSelectedIndex()))) {
                        currentAccount = account;
                        loadAccountInfo();
                        break;
                    }
                }
            }
        });
        copyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String get = currentCode.getText();
                StringSelection selec = new StringSelection(get);
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(selec, selec);
            }
        });
        setupNewAccountButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                LoginForm loginForm = new LoginForm(Dialog.ModalityType.TOOLKIT_MODAL);
                manifest = Manifest.GetManifest(false);
                loadAccountsList();
            }
        });
        removeAccountButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String accountName = (String)listAccounts.getModel().getElementAt(listAccounts.getSelectedIndex());
                String verificationText = (String)JOptionPane.showInputDialog(null, "If you really want to remove Google Authenticator from " + accountName + ", please put \"12345\"", "Remove Google Authenticator", JOptionPane.INFORMATION_MESSAGE, null, null, null);
                while(verificationText != null && !verificationText.equals("12345")) {
                    JOptionPane.showMessageDialog(null, "The verification code is wrong, please try again.", "Wrong code", JOptionPane.WARNING_MESSAGE);
                    verificationText = (String)JOptionPane.showInputDialog(null, "If you really want to remove Google Authenticator from " + accountName + ", please put \"12345\"", "Remove Google Authenticator", JOptionPane.INFORMATION_MESSAGE, null, null, null);
                }
                if (verificationText != null && verificationText.equals("12345")) {
                    JOptionPane.showMessageDialog(null, "Google Authenticator from " + accountName + " removed completely.\nNOTICE: maFile will be deleted after hitting okay. If you need to make a backup, now's the time.", "Remove Google Authenticator", 3, ico);
                    manifest.RemoveAccount(currentAccount, true);
                    loadAccountsList();
                }
            }
        });
        final JPopupMenu popup = new JPopupMenu();
        JMenuItem mi = new JMenuItem();
        mi.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String get = mi.getText();
                StringSelection selec = new StringSelection(get);
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(selec, selec);
            }
        });
        popup.add(mi);
        listAccounts.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                JList list = (JList)e.getSource();
                if (e.getModifiers() == MouseEvent.BUTTON3_MASK) {
                    Rectangle r = list.getCellBounds (0, list.getLastVisibleIndex());
                    if (r != null && r.contains(e.getPoint())) {
                        int index = list.locationToIndex(e.getPoint());
                        list.setSelectedIndex(index);
                        mi.setText(allAccounts.get(index).secure);
                        popup.show(listAccounts, e.getX(), e.getY());
                    }
                }
            }
        });
    }

    /// <summary>
    /// Decrypts files and populates list UI with accounts
    /// </summary>
    private void loadAccountsList() {
        currentAccount = null;

        DefaultListModel listModel = new DefaultListModel();
        listAccounts.setModel(listModel);
        listModel.removeAllElements();
        listAccounts.setSelectedIndex(-1);

        allAccounts = manifest.GetAllAccounts("");

        if (allAccounts.size() > 0) {
            for (int i = 0; i < allAccounts.size(); i++) {
                GAuthAccount account = allAccounts.get(i);
                listModel.add(i, account.name);
            }

            listAccounts.setSelectedIndex(0);
        }
    }

    /// <summary>
    /// Load UI with the current account info, this is run every second
    /// </summary>
    private void loadAccountInfo() {
        if (currentAccount != null) {
            currentCode.setText(gAuth.generate(currentAccount.secure));
        }
    }

    private void timerSteamGuard_Tick() {
        Timer timer = new Timer(1000, new ActionListener() {
            public void actionPerformed(ActionEvent ev) {
                long time = (long)gAuth.getTime();
                long currentSteamChunk = time / 30L;
                int secondsUntilChange = (int)(time - (currentSteamChunk * 30L));

                gAuth.getTime();

                loadAccountInfo();
                if (currentAccount != null)
                {
                    progressBar1.setValue(30 - secondsUntilChange);
                    progressBar1.setString(30 - secondsUntilChange + " sec");
                }
            }
        });
        timer.start();
    }

    public static void main(String args[]) {
        GAForm formSDA = new GAForm();
        formSDA.pack();
        formSDA.setVisible(true);
    }
}
