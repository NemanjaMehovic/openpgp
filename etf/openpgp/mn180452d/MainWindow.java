package etf.openpgp.mn180452d;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;

import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class MainWindow
{

    private JPanel MainPanel;
    private JPanel MainPage;
    private JButton ImportKeyButton;
    private JButton Delete;
    private JButton ExportPublicKey;
    private JButton ExportSecretKey;
    private JTable KeysTable;
    private JButton Encrypt;
    private JButton Decrypt;
    private JButton GenerateKey;
    private JPanel GenerateKeyPair;
    private JTextField Username;
    private JTextField Email;
    private JRadioButton RSA2048RadioButton;
    private JRadioButton RSA1024RadioButton;
    private JRadioButton RSA4096RadioButton;
    private JButton generateButton;
    private JButton cancelButton;
    private JPanel EncryptPage;
    private JList signingList;
    private JList keysList;
    private JCheckBox Signe;
    private JCheckBox Compress;
    private JCheckBox Radix64;
    private JCheckBox AES;
    private JCheckBox TDES;
    private JButton cancelEn;
    private JButton EncryptB;

    public MainWindow()
    {
        setData();
        KeysTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        ImportKeyButton.addActionListener(e ->
        {
            JFileChooser chooser = new JFileChooser();
            FileNameExtensionFilter filter = new FileNameExtensionFilter(".asc", "asc");
            chooser.setFileFilter(filter);
            int returnVal = chooser.showOpenDialog(MainPage);
            if (returnVal == JFileChooser.APPROVE_OPTION)
            {
                try
                {
                    if (Keys.getInstance().ImportKey(chooser.getSelectedFile().toString()))
                    {
                        try
                        {
                            String password = getPasswordDialog("Enter password for secret key:");
                            Keys.getInstance().ImportPrivateKey(Keys.getInstance().importedSecretKeyRing, password);
                        }
                        catch (Exception ex)
                        {
                            JOptionPane.showMessageDialog(new JFrame(), "Wrong password", "Error", JOptionPane.ERROR_MESSAGE);
                        }
                    }
                }
                catch (Exception ex)
                {
                    JOptionPane.showMessageDialog(new JFrame(), "File does not contain a key.", "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
            setData();
        });
        ExportPublicKey.addActionListener(e ->
        {
            int row = KeysTable.getSelectedRow();
            if(row == -1)
            {
                JOptionPane.showMessageDialog(new JFrame(), "No key pair selected", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            JFileChooser chooser = new JFileChooser();
            FileNameExtensionFilter filter = new FileNameExtensionFilter(".asc", "asc");
            chooser.setFileFilter(filter);
            int returnVal = chooser.showOpenDialog(MainPage);
            if (returnVal == JFileChooser.APPROVE_OPTION)
            {
                String tmpString = chooser.getSelectedFile().toString();
                if (!tmpString.contains(".asc"))
                    tmpString = tmpString + ".asc";
                try
                {
                    Keys.getInstance().ExportPublicKey(Keys.getInstance().getAllKeys().get(row), tmpString);
                }
                catch (Exception ex)
                {
                    ex.printStackTrace();
                    JOptionPane.showMessageDialog(new JFrame(), "Failed to export public key", "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        ExportSecretKey.addActionListener(e ->
        {
            int row = KeysTable.getSelectedRow();
            if(row == -1)
            {
                JOptionPane.showMessageDialog(new JFrame(), "No key pair selected", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            if(Keys.getInstance().getAllKeys().get(row).keyPair.getPrivateKey() == null)
            {
                JOptionPane.showMessageDialog(new JFrame(), "Does not have private key", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            JFileChooser chooser = new JFileChooser();
            FileNameExtensionFilter filter = new FileNameExtensionFilter(".asc", "asc");
            chooser.setFileFilter(filter);
            int returnVal = chooser.showOpenDialog(MainPage);
            if (returnVal == JFileChooser.APPROVE_OPTION)
            {
                String tmpString = chooser.getSelectedFile().toString();
                if (!tmpString.contains(".asc"))
                    tmpString = tmpString + ".asc";
                try
                {
                    Keys.getInstance().ExportPrivateKey(Keys.getInstance().getAllKeys().get(row), tmpString);
                }
                catch (Exception ex)
                {
                    ex.printStackTrace();
                    JOptionPane.showMessageDialog(new JFrame(), "Failed to export secret key", "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        Delete.addActionListener(e ->
        {
            int row = KeysTable.getSelectedRow();
            if(row == -1)
            {
                JOptionPane.showMessageDialog(new JFrame(), "No key pair selected", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            Keys.KeyData keyData = Keys.getInstance().getAllKeys().get(row);
            if(keyData.keyPair.getPrivateKey() == null || keyData.password == null)
            {
                Keys.getInstance().getAllKeys().remove(keyData);
                setData();
                return;
            }
            String password = getPasswordDialog("Enter password for key pair you wish to delete.");
            if(password.equals(keyData.password))
            {
                Keys.getInstance().getAllKeys().remove(keyData);
                setData();
            }
            else
                JOptionPane.showMessageDialog(new JFrame(), "Wrong password", "Error", JOptionPane.ERROR_MESSAGE);
        });
        GenerateKey.addActionListener(e ->
        {
            MainPage.setVisible(false);
            GenerateKeyPair.setVisible(true);
        });
        cancelButton.addActionListener(e ->
        {
            GenerateKeyPair.setVisible(false);
            MainPage.setVisible(true);
        });
        generateButton.addActionListener(e ->
        {
            String username = Username.getText();
            String email = Email.getText();
            Keys.RSA_Key_Size size = null;
            if(RSA1024RadioButton.isSelected())
                size = Keys.RSA_Key_Size.RSA1024;
            else if(RSA2048RadioButton.isSelected())
                size = Keys.RSA_Key_Size.RSA2048;
            else
                size = Keys.RSA_Key_Size.RSA4096;
            if(username.equals(""))
            {
                JOptionPane.showMessageDialog(new JFrame(), "Username not entered.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            if(email.equals(""))
            {
                JOptionPane.showMessageDialog(new JFrame(), "Email not entered.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            email = "<" + email.trim() + ">";
            String UserId = username.trim() + " " + email;
            String password = getPasswordDialog("Enter password for new key pair");
            if(password.equals(""))
            {
                JOptionPane.showMessageDialog(new JFrame(), "No password entered.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            try
            {
                Keys.getInstance().GenerateNewKeyPair(UserId, password, size);
                setData();
                GenerateKeyPair.setVisible(false);
                MainPage.setVisible(true);
            }
            catch (Exception exception)
            {
                JOptionPane.showMessageDialog(new JFrame(), exception.toString(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        });
        Decrypt.addActionListener(e ->
        {
            JFileChooser chooser = new JFileChooser();
            FileNameExtensionFilter filter = new FileNameExtensionFilter(".asc/.pgp/.gpg", "asc", "pgp", "gpg");
            chooser.setDialogTitle("File to decrypt");
            chooser.setFileFilter(filter);
            int returnVal = chooser.showOpenDialog(MainPage);
            if (returnVal == JFileChooser.APPROVE_OPTION)
            {
                String tmpString = chooser.getSelectedFile().toString();
                try
                {
                    PGP.PGPDecryptionImplementation(tmpString);
                    boolean flag = false;
                    for(Keys.KeyData tmpData : PGP.neededKey)
                        if(tmpData.password == null)
                        {
                            chooser = new JFileChooser();
                            chooser.setDialogTitle("Location to save file");
                            returnVal = chooser.showOpenDialog(MainPage);
                            if (returnVal == JFileChooser.APPROVE_OPTION)
                            {
                                PGP.exportData(chooser.getSelectedFile().toString());
                                JOptionPane.showMessageDialog(new JFrame(), PGP.decryptionStatus.toString(), "Status", JOptionPane.INFORMATION_MESSAGE);
                                return;
                            }
                        }
                    for(Keys.KeyData tmpData : PGP.neededKey)
                    {
                        String password = getPasswordDialog("Enter password for " + tmpData.userId + " " + String.format("%X", tmpData.keyPair.getKeyID()));
                        if(password.equals(tmpData.password))
                        {
                            flag = true;
                            break;
                        }
                    }
                    if(flag || PGP.neededKey.size() == 0)
                    {
                        chooser = new JFileChooser();
                        chooser.setDialogTitle("Location to save file");
                        returnVal = chooser.showOpenDialog(MainPage);
                        if (returnVal == JFileChooser.APPROVE_OPTION)
                        {
                            PGP.exportData(chooser.getSelectedFile().toString());
                            JOptionPane.showMessageDialog(new JFrame(), PGP.decryptionStatus.toString(), "Status", JOptionPane.INFORMATION_MESSAGE);
                        }
                    }
                    else
                        JOptionPane.showMessageDialog(new JFrame(), "All passwords entered were incorrect", "Error", JOptionPane.ERROR_MESSAGE);
                }
                catch (Exception exception)
                {
                    exception.printStackTrace();
                    JOptionPane.showMessageDialog(new JFrame(), exception.toString(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        cancelEn.addActionListener(e ->
        {
            EncryptPage.setVisible(false);
            MainPage.setVisible(true);
        });
        Encrypt.addActionListener(e ->
        {
            MainPage.setVisible(false);
            EncryptPage.setVisible(true);
        });
        AES.addActionListener(e ->
        {
            if(AES.isSelected())
                TDES.setSelected(false);
        });
        TDES.addActionListener(e ->
        {
            if(TDES.isSelected())
                AES.setSelected(false);
        });
        EncryptB.addActionListener(e ->
        {
            Keys.KeyData signerData = null;
            List<Keys.KeyData> receivers = new ArrayList<>();
            List<Keys.KeyData> signingKeys = new ArrayList<>();
            for(Keys.KeyData tmp : Keys.getInstance().getAllKeys())
                if(tmp.keyPair.getPrivateKey() != null)
                    signingKeys.add(tmp);
            int[] indexesR = keysList.getSelectedIndices();
            int[] signer = signingList.getSelectedIndices();
            if(Signe.isSelected())
            {
                if(signer.length == 0)
                {
                    JOptionPane.showMessageDialog(new JFrame(), "No signer selected", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                if(signingKeys.get(signer[0]).password != null)
                {
                    String password = getPasswordDialog("Enter password for key " + signingKeys.get(signer[0]).userId + String.format(" %X", signingKeys.get(signer[0]).keyPair.getKeyID()));
                    if(!password.equals(signingKeys.get(signer[0]).password))
                    {
                        JOptionPane.showMessageDialog(new JFrame(), "Wrong password entered", "Error", JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                    signerData = signingKeys.get(signer[0]);
                }
            }
            if(AES.isSelected() || TDES.isSelected())
            {
                if(indexesR.length == 0)
                {
                    JOptionPane.showMessageDialog(new JFrame(), "No receivers selected", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                for(int tmp : indexesR)
                    receivers.add(Keys.getInstance().getAllKeys().get(tmp));
            }
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("File to encrypt");
            int returnVal = chooser.showOpenDialog(MainPage);
            if(returnVal == JFileChooser.CANCEL_OPTION)
            {
                JOptionPane.showMessageDialog(new JFrame(), "No file selected to encrypt", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            String inFile = chooser.getSelectedFile().toString();
            chooser = new JFileChooser();
            chooser.setDialogTitle("Location to save file");
            returnVal = chooser.showOpenDialog(MainPage);
            if(returnVal == JFileChooser.CANCEL_OPTION)
            {
                JOptionPane.showMessageDialog(new JFrame(), "No file selected as destination", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            String outFile = chooser.getSelectedFile().toString();
            try
            {
                PGP.PGPEncryptImplementation(inFile, outFile, signerData, receivers, Signe.isSelected(), AES.isSelected(), TDES.isSelected(), Compress.isSelected(), Radix64.isSelected());
            }
            catch (Exception exception)
            {
                exception.printStackTrace();
                JOptionPane.showMessageDialog(new JFrame(), exception.toString(), "Error", JOptionPane.ERROR_MESSAGE);
            }
            MainPage.setVisible(true);
            EncryptPage.setVisible(false);
        });
    }

    private String getPasswordDialog(String s)
    {
        JPasswordField password = new JPasswordField();
        final JComponent[] inputs = new JComponent[] {new JLabel(s), password};
        JOptionPane.showConfirmDialog(MainPanel, inputs, "Password dialog", JOptionPane.DEFAULT_OPTION);
        return String.valueOf(password.getPassword());
    }

    public void setData()
    {
        List<List<String>> list = new ArrayList<>();
        for(Keys.KeyData tmp : Keys.getInstance().getAllKeys())
            list.add(Arrays.asList(tmp.userId, String.valueOf(tmp.keyPair.getPublicKey().getBitStrength()), tmp.keyPair.getPrivateKey() != null ? "Yes" : "No", String.format("0x%X", tmp.keyPair.getKeyID())));
        Object[][] keys = new Object[list.size()][4];
        for(int i = 0; i < list.size(); i++)
        {
            String[] val = (String[]) list.get(i).toArray();
            System.arraycopy(val, 0, keys[i], 0, val.length);
        }
        TableModel model = new DefaultTableModel(keys, new String[]{"UserId", "Strength", "Has private key", "KeyID"}){
            @Override
            public boolean isCellEditable(int i, int i1) {
                return false;
            }
        };
        KeysTable.setModel(model);

        DefaultListModel  listModelAllKeys = new DefaultListModel();
        DefaultListModel  listSigneKeys = new DefaultListModel();
        for(Keys.KeyData tmp : Keys.getInstance().getAllKeys())
        {
            listModelAllKeys.addElement(tmp.userId + " " + String.format("%X", tmp.keyPair.getKeyID()));
            if(tmp.keyPair.getPrivateKey() != null)
                listSigneKeys.addElement(tmp.userId + " " + String.format("%X", tmp.keyPair.getKeyID()));
        }
        keysList.setModel(listModelAllKeys);
        signingList.setModel(listSigneKeys);
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        JFrame frame = new JFrame("ZP_projekat");
        frame.setContentPane(new MainWindow().MainPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setMinimumSize(new Dimension(700,500));
        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

}
