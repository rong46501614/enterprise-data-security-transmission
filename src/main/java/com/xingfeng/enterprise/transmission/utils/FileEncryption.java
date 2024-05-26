package com.xingfeng.enterprise.transmission.utils;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

public class FileEncryption {

    public static final String sourceFolder = "E:\\DevelopmentCode\\enterprise-data-security-transmission\\src";

    public static void main(String[] args) {
        String key = readFileByLine("C:\\Users\\xingfeng\\Desktop\\github-file-passwd.txt");
        encrypt(key);
//        decrypt(key);
    }

    public static void encrypt(String key) {
        Set<String> fileSet = new HashSet<>();
        traverseFolder(sourceFolder, fileSet);
        for (String path: fileSet ) {
            File file = new File(path);
            String name = file.getName();
            String s = file.getParentFile().getAbsolutePath() + "\\"+ Base64.getEncoder().encodeToString(name.getBytes());
            aesFileForInput(path, s, key, Cipher.ENCRYPT_MODE);
            file.delete();
        }
    }


    public static void decrypt(String key) {
        Set<String> fileSet = new HashSet<>();
        traverseFolder(sourceFolder, fileSet);
        for (String path: fileSet ) {
            File file = new File(path);
            String name = file.getName();
            String s = file.getParentFile().getAbsolutePath() + "\\"+ new String(Base64.getDecoder().decode(name));
            aesFileForInput(path, s, key, Cipher.DECRYPT_MODE);
            file.delete();
        }
    }

    private static Cipher getCipher(int mode, byte[] key) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(mode, secretKeySpec);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return cipher;
    }

    //InputStream Encryption/Decryption
    public static void aesFileForInput(String sourceFilePath,
                                       String destFilePath,
                                       String key,
                                       int mode) {
        File sourceFile = new File(sourceFilePath);
        File destFile = new File(destFilePath);
        if (!destFile.getParentFile().exists()) {
            destFile.getParentFile().mkdirs();
        }
        InputStream in = null;
        CipherInputStream cin = null;
        try {
            destFile.createNewFile();
            in = new FileInputStream(sourceFile);
            Cipher cipher = getCipher(mode, Base64.getDecoder().decode(key));
            cin = new CipherInputStream(in, cipher);
            int bufferSize = 1024;
            byte[] cache = new byte[bufferSize];
            int nRead = 0;
            while ((nRead = cin.readNBytes(cache, 0, bufferSize)) != 0) {
                RandomAccessFile randomAccessFile = new RandomAccessFile(destFilePath, "rw");
                long fileLenght = randomAccessFile.length();
                randomAccessFile.seek(fileLenght);
                randomAccessFile.write(cache, 0, nRead);
                randomAccessFile.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (cin != null)
                    cin.close();
                if (in != null)
                    in.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void traverseFolder(String rootFolderPath, Set<String> fileSet) {

        File rootFolder = new File(rootFolderPath);
        File[] listOfFiles = rootFolder.listFiles();
        if (listOfFiles == null) {
            return;
        }
        for (File file : listOfFiles) {
            if (file.isFile()) {
                if(!file.getAbsolutePath().contains("FileEncryption.java"))
                fileSet.add(file.getAbsolutePath());
            } else if (file.isDirectory()) {
                traverseFolder(file.getAbsolutePath(), fileSet); // 递归遍历子文件夹
            }
        }
    }

    public static String readFileByLine(String filePath) {
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader(filePath));
            String line = reader.readLine();
            if(line != null){
                return line;
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "";
    }
}
