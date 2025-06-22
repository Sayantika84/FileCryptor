import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.UnsupportedLookAndFeelException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.SecretKeyFactory;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.*;
import java.io.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.nio.file.Files;
import java.nio.file.Paths;

public class FileEncryptionApp extends JFrame {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KEY_LENGTH = 256;
    private static final int IV_LENGTH = 16;
    private static final int SALT_LENGTH = 16;
    private static final int ITERATION_COUNT = 100000;
    
    private JList<File> fileList;
    private DefaultListModel<File> listModel;
    private JTextArea logArea;
    private JPasswordField passwordField;
    private JProgressBar progressBar;
    private JButton encryptButton;
    private JButton decryptButton;
    private JButton addFilesButton;
    private JButton clearListButton;
    private JLabel statusLabel;
    private ExecutorService executor;
    
    public FileEncryptionApp() {
        setTitle("Secure File Encryption/Decryption Tool");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());
        
        executor = Executors.newSingleThreadExecutor();
        initializeComponents();
        setupLayout();
        setupEventHandlers();
        setupDragAndDrop();
        
        setSize(800, 700);
        setLocationRelativeTo(null);
        setVisible(true);
    }
    
    private void initializeComponents() {
        // File list
        listModel = new DefaultListModel<>();
        fileList = new JList<>(listModel);
        fileList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        fileList.setCellRenderer(new FileListCellRenderer());
        
        // Buttons
        addFilesButton = new JButton("Add Files");
        clearListButton = new JButton("Clear List");
        encryptButton = new JButton("Encrypt Files");
        decryptButton = new JButton("Decrypt Files");
        
        // Password field
        passwordField = new JPasswordField(20);
        
        // Progress bar
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setString("Ready");
        
        // Status label
        statusLabel = new JLabel("Ready to process files");
        
        // Log area
        logArea = new JTextArea(10, 50);
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logArea.setBackground(new Color(248, 248, 248));
    }
    
    private void setupLayout() {
        // Main panel
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // File selection panel
        JPanel filePanel = new JPanel(new BorderLayout(5, 5));
        filePanel.setBorder(new TitledBorder("File Selection"));
        
        JScrollPane fileScrollPane = new JScrollPane(fileList);
        fileScrollPane.setPreferredSize(new Dimension(400, 200));
        fileScrollPane.setBorder(BorderFactory.createLoweredBevelBorder());
        
        JPanel fileButtonPanel = new JPanel(new FlowLayout());
        fileButtonPanel.add(addFilesButton);
        fileButtonPanel.add(clearListButton);
        
        JLabel dropLabel = new JLabel("Drag and drop files here or use 'Add Files' button", JLabel.CENTER);
        dropLabel.setForeground(Color.GRAY);
        dropLabel.setFont(dropLabel.getFont().deriveFont(Font.ITALIC));
        
        filePanel.add(dropLabel, BorderLayout.NORTH);
        filePanel.add(fileScrollPane, BorderLayout.CENTER);
        filePanel.add(fileButtonPanel, BorderLayout.SOUTH);
        
        // Control panel
        JPanel controlPanel = new JPanel(new GridBagLayout());
        controlPanel.setBorder(new TitledBorder("Encryption/Decryption"));
        GridBagConstraints gbc = new GridBagConstraints();
        
        gbc.gridx = 0; gbc.gridy = 0; gbc.anchor = GridBagConstraints.WEST;
        controlPanel.add(new JLabel("Password:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 0; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        controlPanel.add(passwordField, gbc);
        
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(10, 0, 0, 0);
        JPanel buttonPanel = new JPanel(new FlowLayout());
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);
        controlPanel.add(buttonPanel, gbc);
        
        // Progress panel
        JPanel progressPanel = new JPanel(new BorderLayout(5, 5));
        progressPanel.setBorder(new TitledBorder("Progress"));
        progressPanel.add(progressBar, BorderLayout.CENTER);
        progressPanel.add(statusLabel, BorderLayout.SOUTH);
        
        // Log panel
        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(new TitledBorder("Operation Log"));
        JScrollPane logScrollPane = new JScrollPane(logArea);
        logScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        logPanel.add(logScrollPane, BorderLayout.CENTER);
        
        // Assemble main layout
        JPanel topPanel = new JPanel(new BorderLayout(10, 10));
        topPanel.add(filePanel, BorderLayout.CENTER);
        topPanel.add(controlPanel, BorderLayout.EAST);
        
        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(progressPanel, BorderLayout.CENTER);
        mainPanel.add(logPanel, BorderLayout.SOUTH);
        
        add(mainPanel, BorderLayout.CENTER);
    }
    
    private void setupEventHandlers() {
        addFilesButton.addActionListener(e -> addFiles());
        clearListButton.addActionListener(e -> clearFileList());
        encryptButton.addActionListener(e -> processFiles(true));
        decryptButton.addActionListener(e -> processFiles(false));
        
        // Enter key in password field triggers encryption
        passwordField.addActionListener(e -> {
            if (listModel.getSize() > 0) {
                processFiles(true);
            }
        });
    }
    
    private void setupDragAndDrop() {
        new DropTarget(fileList, new DropTargetListener() {
            @Override
            public void dragEnter(DropTargetDragEvent dtde) {
                dtde.acceptDrag(DnDConstants.ACTION_COPY);
            }
            
            @Override
            public void dragOver(DropTargetDragEvent dtde) {}
            
            @Override
            public void dropActionChanged(DropTargetDragEvent dtde) {}
            
            @Override
            public void dragExit(DropTargetEvent dte) {}
            
            @Override
            public void drop(DropTargetDropEvent dtde) {
                try {
                    dtde.acceptDrop(DnDConstants.ACTION_COPY);
                    @SuppressWarnings("unchecked")
                    List<File> droppedFiles = (List<File>) dtde.getTransferable()
                            .getTransferData(DataFlavor.javaFileListFlavor);
                    
                    for (File file : droppedFiles) {
                        if (file.isFile() && !listModel.contains(file)) {
                            listModel.addElement(file);
                            logMessage("Added file: " + file.getName());
                        }
                    }
                    dtde.dropComplete(true);
                } catch (Exception e) {
                    logMessage("Error adding dropped files: " + e.getMessage());
                    dtde.dropComplete(false);
                }
            }
        });
    }
    
    private void addFiles() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setMultiSelectionEnabled(true);
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File[] selectedFiles = fileChooser.getSelectedFiles();
            for (File file : selectedFiles) {
                if (!listModel.contains(file)) {
                    listModel.addElement(file);
                    logMessage("Added file: " + file.getName());
                }
            }
        }
    }
    
    private void clearFileList() {
        listModel.clear();
        logMessage("File list cleared");
    }
    
    private void processFiles(boolean encrypt) {
        char[] password = passwordField.getPassword();
        
        if (password.length == 0) {
            JOptionPane.showMessageDialog(this, "Please enter a password", "Password Required", 
                    JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        if (listModel.getSize() == 0) {
            JOptionPane.showMessageDialog(this, "Please add files to process", "No Files Selected", 
                    JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        // Disable buttons during processing
        setButtonsEnabled(false);
        
        executor.submit(() -> {
            try {
                List<File> files = new ArrayList<>();
                for (int i = 0; i < listModel.getSize(); i++) {
                    files.add(listModel.getElementAt(i));
                }
                
                SwingUtilities.invokeLater(() -> {
                    progressBar.setMaximum(files.size());
                    progressBar.setValue(0);
                    progressBar.setString("Processing...");
                });
                
                int processed = 0;
                int successful = 0;
                
                for (File file : files) {
                    try {
                        SwingUtilities.invokeLater(() -> {
                            statusLabel.setText("Processing: " + file.getName());
                            logMessage((encrypt ? "Encrypting: " : "Decrypting: ") + file.getName());
                        });
                        
                        if (encrypt) {
                            encryptFile(file, password);
                        } else {
                            decryptFile(file, password);
                        }
                        
                        successful++;
                        SwingUtilities.invokeLater(() -> 
                            logMessage("Successfully " + (encrypt ? "encrypted" : "decrypted") + ": " + file.getName()));
                        
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> 
                            logMessage("Error processing " + file.getName() + ": " + e.getMessage()));
                    }
                    
                    processed++;
                    final int currentProgress = processed;
                    SwingUtilities.invokeLater(() -> progressBar.setValue(currentProgress));
                }
                
                final int finalSuccessful = successful;
                final int totalFiles = files.size();
                
                SwingUtilities.invokeLater(() -> {
                    progressBar.setString("Complete");
                    statusLabel.setText("Processed " + finalSuccessful + "/" + totalFiles + " files successfully");
                    logMessage("Operation completed: " + finalSuccessful + "/" + totalFiles + " files processed successfully");
                    setButtonsEnabled(true);
                    
                    // Clear password for security
                    passwordField.setText("");
                    
                    if (finalSuccessful == totalFiles) {
                        JOptionPane.showMessageDialog(this, 
                            "All files processed successfully!", 
                            "Success", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(this, 
                            "Processed " + finalSuccessful + " out of " + totalFiles + " files. Check log for details.", 
                            "Partial Success", JOptionPane.WARNING_MESSAGE);
                    }
                });
                
            } finally {
                // Clear password from memory
                java.util.Arrays.fill(password, '\0');
            }
        });
    }
    
    private void encryptFile(File inputFile, char[] password) throws Exception {
        // Generate salt for key derivation
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        
        // Generate IV
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        
        // Derive key from password
        SecretKey key = deriveKeyFromPassword(password, salt);
        
        // Create cipher
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        
        // Create output file
        File outputFile = new File(inputFile.getAbsolutePath() + ".enc");
        
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            
            // Write salt and IV to the beginning of the encrypted file
            fos.write(salt);
            fos.write(iv);
            
            // Encrypt file in chunks
            byte[] buffer = new byte[8192];
            int bytesRead;
            
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] encryptedChunk = cipher.update(buffer, 0, bytesRead);
                if (encryptedChunk != null) {
                    fos.write(encryptedChunk);
                }
            }
            
            // Write final block
            byte[] finalBlock = cipher.doFinal();
            if (finalBlock != null) {
                fos.write(finalBlock);
            }
        }
    }
    
    private void decryptFile(File inputFile, char[] password) throws Exception {
        if (!inputFile.getName().endsWith(".enc")) {
            throw new IllegalArgumentException("File does not appear to be encrypted (missing .enc extension)");
        }
        
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            // Read salt and IV from the beginning of the file
            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[IV_LENGTH];
            
            if (fis.read(salt) != SALT_LENGTH || fis.read(iv) != IV_LENGTH) {
                throw new IllegalArgumentException("Invalid encrypted file format");
            }
            
            // Derive key from password
            SecretKey key = deriveKeyFromPassword(password, salt);
            
            // Create cipher
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            
            // Create output file (remove .enc extension)
            String outputPath = inputFile.getAbsolutePath();
            outputPath = outputPath.substring(0, outputPath.length() - 4); // Remove .enc
            File outputFile = new File(outputPath);
            
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                // Decrypt file in chunks
                byte[] buffer = new byte[8192];
                int bytesRead;
                
                while ((bytesRead = fis.read(buffer)) != -1) {
                    byte[] decryptedChunk = cipher.update(buffer, 0, bytesRead);
                    if (decryptedChunk != null) {
                        fos.write(decryptedChunk);
                    }
                }
                
                // Write final block
                byte[] finalBlock = cipher.doFinal();
                if (finalBlock != null) {
                    fos.write(finalBlock);
                }
            }
        }
    }
    
    private SecretKey deriveKeyFromPassword(char[] password, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(password, salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }
    
    private void setButtonsEnabled(boolean enabled) {
        encryptButton.setEnabled(enabled);
        decryptButton.setEnabled(enabled);
        addFilesButton.setEnabled(enabled);
        clearListButton.setEnabled(enabled);
    }
    
    private void logMessage(String message) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = java.time.LocalTime.now().toString().substring(0, 8);
            logArea.append("[" + timestamp + "] " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }
    
    // Custom cell renderer for file list
    private static class FileListCellRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            
            if (value instanceof File) {
                File file = (File) value;
                setText(file.getName() + " (" + formatFileSize(file.length()) + ")");
                setIcon(getFileIcon(file));
            }
            
            return this;
        }
        
        private String formatFileSize(long bytes) {
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
            if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
            return String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024));
        }
        
        private Icon getFileIcon(File file) {
            if (file.getName().endsWith(".enc")) {
                return UIManager.getIcon("FileView.computerIcon");
            }
            return UIManager.getIcon("FileView.fileIcon");
        }
    }
    
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new FileEncryptionApp());
    }
}