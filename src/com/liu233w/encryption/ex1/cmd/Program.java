package com.liu233w.encryption.ex1.cmd;

import com.liu233w.encryption.ex1.CaesarCipher;
import com.liu233w.encryption.ex1.PlayfairCipher;
import com.liu233w.encryption.ex1.RsaCipher;
import com.liu233w.encryption.ex1.RsaKeyPair;

import java.math.BigInteger;
import java.util.InputMismatchException;
import java.util.Scanner;

public class Program {

    private static Scanner scanner;

    public static void main(String[] args) {

        scanner = new Scanner(System.in);

        while (true) {
            System.out.println("Choose a algorithm:\n" +
                    "(1) Caesar\n" +
                    "(2) Playfair\n" +
                    "(3) RSA\n" +
                    "(0) EXIT\n" +
                    "Enter the number: ");

            try {

                final int i = scanner.nextInt();

                switch (i) {
                    case 0:
                        System.out.println("Bye.");
                        return;
                    case 1:
                        caesar();
                        break;
                    case 2:
                        playfair();
                        break;
                    case 3:
                        rsa();
                        break;
                    default:
                        throw new IllegalArgumentException("Please enter the number on the list");
                }
            } catch (IllegalArgumentException e) {
                System.err.println(e.getMessage());
            } catch (InputMismatchException e) {
                System.err.printf("Input mismatch: %s\n", e.getMessage());
                clearBuffer();
            }
        }
    }

    private static void rsa() {
        System.out.println("Generating keys, please stand by...");
        final RsaKeyPair rsaKeyPair = RsaCipher.generateKey();

        System.out.printf("Public key: %s\nPrivate key: %s\n", rsaKeyPair.getPublicKey(), rsaKeyPair.getPrivateKey());

        try {
            while (true) {
                System.out.print("(e) Encrypt\n" +
                        "(d) Decrypt\n" +
                        "(x) Exit\n" +
                        "command [e,d,x] > ");
                final String cmd = scanner.next();

                switch (cmd) {
                    case "x":
                        return;
                    case "e": {
                        System.out.print("Enter your plain text: ");
                        scanner.nextLine(); // consume line end
                        final String text = scanner.nextLine();
                        final BigInteger input = new BigInteger(text.getBytes());

                        System.out.printf("Result: %s\n", RsaCipher.encrypt(input, rsaKeyPair.getPublicKey()));
                        break;
                    }
                    case "d": {
                        System.out.print("Enter your cypher text (integer only): ");
                        final String text = scanner.next();
                        final BigInteger res = RsaCipher.decrypt(new BigInteger(text), rsaKeyPair.getPrivateKey());
                        System.out.printf("Result: %s\n", new String(res.toByteArray()));
                        break;
                    }
                    default:
                        throw new IllegalArgumentException("Please enter the command on the list");
                }
            }
        } catch (NumberFormatException e) {
            System.err.printf("Number Error: %s\n", e.getMessage());
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
        } catch (InputMismatchException e) {
            System.err.printf("Input mismatch: %s\n", e.getMessage());
            clearBuffer();
        }
    }

    private static void playfair() {
        System.out.print("Enter text (upper alphabet only): ");
        scanner.nextLine(); // consume line end
        final String text = scanner.nextLine();
        System.out.print("Enter the key(upper alphabet only): ");
        final String key = scanner.nextLine();

        final PlayfairCipher playfairCipher = new PlayfairCipher(key);

        System.out.printf("Result: %s\n\n", playfairCipher.encrypt(text));
    }

    private static void caesar() {
        System.out.print("Enter text: ");
        scanner.nextLine(); // consume line end
        final String text = scanner.nextLine();
        System.out.print("Enter the key(-26 ~ 26): ");
        final int key = scanner.nextInt();
        System.out.printf("Result: %s\n\n", CaesarCipher.encrypt(text, key));
    }

    private static void clearBuffer() {
        scanner.nextLine();
    }
}
