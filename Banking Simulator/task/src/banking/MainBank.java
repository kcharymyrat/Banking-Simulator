package banking;

import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.nio.file.Path;
import java.nio.file.Paths;

public class MainBank {
    static List<String> list = new ArrayList<>();
    private static final Scanner scanner = new Scanner(System.in);


    public static void main(String[] args) throws IOException {
//        Path currentPath = Paths.get("");
//        System.out.println("Current Path: " + currentPath.toAbsolutePath());
//        // Current Path: D:\JetBrainsWork\Banking Simulator\Banking Simulator\task

        final String filePath = ".\\userData.txt";


        List<String> usernames = getUsernames(filePath);

        String login = "";
        String password = "";

        System.out.println("Registration");

        login = getLoginInputRecursive(usernames);
        password = getPasswordInputRecursive();

        addUsernameToFile(login, password, filePath);
        usernames = getUsernames(filePath);

        System.out.println();
        System.out.println("Enter the data again to complete the registration");

        while (true) {
            System.out.println("Login:");
            String loginTrial = cleanLogin(getInput());

            System.out.println("Password:");
            String passwordTrial = getInput();

            if (!login.equalsIgnoreCase(loginTrial) && !password.equalsIgnoreCase(passwordTrial)) {
                System.out.println();
                System.out.println("Login and password don't match.");
            } else if (!login.equalsIgnoreCase(loginTrial)) {
                System.out.println();
                System.out.println("Login doesn't match.");
            } else if (!password.equalsIgnoreCase(passwordTrial)) {
                System.out.println();
                System.out.println("Passwords don't match");
            }

            if (login.equalsIgnoreCase(loginTrial) && password.equalsIgnoreCase(passwordTrial)) {
                break;
            }
        }

        System.out.println();
        System.out.println("Now you can log in for finishing the registration.");
        System.out.println("Login:");
        String loginFinish = cleanLogin(getInput());

        System.out.println("Password:");
        String passwordFinish = getInput();

        if (login.equalsIgnoreCase(loginFinish) && password.equalsIgnoreCase(passwordFinish)) {
            System.out.println("Authorization successful");
            System.out.println("Congratulations on your successful registration!");
        } else {
            System.out.println("Authorization failed");
        }

        scanner.close();
    }



    private static String getInput() {
        return scanner.nextLine().strip().trim();
    }


    private static String getLoginInputRecursive(List<String> usernames) {
        System.out.println("Login:");
        String login = cleanLogin(getInput());

        if (!isValidPhoneNumber(login)) {
            System.out.println("Wrong login format, try again");
            return getLoginInputRecursive(usernames);
        }

        if (usernames.contains(login) || usernames.contains("+" + login)) {
            System.out.println("Login is already taken, try another login");
            return getLoginInputRecursive(usernames);
        }

        return login;

    }

    private static String getPasswordInputRecursive() {
        System.out.println("Password:");
        String password = getInput().trim();
        if (!isValidPassword(password)){
            System.out.println("Wrong password format, try again");
            return getPasswordInputRecursive();
        }
        return password;
    }

    private static List<String> getUsernames(String filePath) {
        File file = new File(filePath);
        List<String> usernames = new ArrayList<>();
        try (Scanner scanner = new Scanner(file)) {
            while (scanner.hasNext()) {
                String line = scanner.nextLine();
                String username = line.split(", ")[0].split(": ")[1];
//                System.out.printf("username = %s\n", username);
                usernames.add(username);
            }
        } catch (FileNotFoundException e) {
            System.out.println("No file found: " + "userData.txt");
        }

        return usernames;
    }

    private static void addUsernameToFile(String username, String password, String filePath) throws IOException {
        // Get the current date and time
        LocalDateTime currentDateTime = LocalDateTime.now();

        // Define the format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

        // Format the current date and time
        String formattedDateTime = currentDateTime.format(formatter);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath, true))) {
            String line = "Login: " + username + ", Password: " + password + ", Registration time: " + formattedDateTime;
            writer.write(line);
            writer.newLine(); // Add a newline after the line
        }
    }

    private static String cleanLogin(String login) {
        var loginStringBuilder = new StringBuilder();

        for (char ch : login.toCharArray()) {
            String chStr = String.valueOf(ch);
            if (chStr.matches("\\d")) {
                loginStringBuilder.append(chStr);
            }
        }
        return loginStringBuilder.toString();
    }

    public static boolean isValidPhoneNumber(String phoneNumber) {
        String pattern = "^\\+?1?(?:-?\\(\\d{1,3}\\)-?|\\s?\\d{1,3}(?:-?\\d{3}){3})$";
        return phoneNumber.matches(pattern);
    }

    public static boolean isValidPassword(String password) {
        String pattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d!@#$%]+(\\s?[a-zA-Z\\d!@#$%]+)*$";
        return password.matches(pattern) && password.length() >= 6 && password.length() <= 28;
    }
}
