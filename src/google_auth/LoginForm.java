package google_auth;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.MalformedURLException;
import java.net.URL;

public class LoginForm extends JDialog {
    private JPanel rootPanel;
    private JTextField textName;
    private JTextField textSecure;
    private JButton OKButton;

    public LoginForm(ModalityType type) {
        setContentPane(rootPanel);
        createListeners();
        setLocationRelativeTo(null);
        pack();
        if (type != null) setModalityType(ModalityType.TOOLKIT_MODAL);
        setTitle("Login");
        try {
            Image img = Toolkit.getDefaultToolkit().getImage(new URL("https://www.shareicon.net/data/16x16/2017/02/15/878904_media_512x512.png"));
            setIconImage(img);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        Dimension screen = Toolkit.getDefaultToolkit().getScreenSize();
        setLocation((screen.width - getWidth()) / 2, (screen.height - getHeight()) / 2);
        setVisible(true);
    }

    public void createListeners() {
        OKButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                addNewAccount();
            }
        });
    }

    public void addNewAccount() {
        Manifest manifest = Manifest.GetManifest(false);
        GAuthAccount account = new GAuthAccount();
        account.name = textName.getText();
        account.secure = textSecure.getText();
        manifest.SaveAccount(account, false, null);
        this.dispose();
    }
}
