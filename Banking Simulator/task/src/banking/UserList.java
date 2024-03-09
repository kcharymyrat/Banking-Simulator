package banking;

import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

import static banking.PasswordUtils.*;

public class UserList {
    private ArrayList<UserDetail> users;

    static List<UserDetail> getUserDetailList(String filePath) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");
        File file = new File(filePath);
        List<UserDetail> userDetailList = new ArrayList<>();
        // System.out.printf("File = %s\n", file);

        String fieldsSeparator = "\\|";
        String keyValueSeparator = ": ";

        try (Scanner scanner = new Scanner(file)) {
            while (scanner.hasNext()) {
                UserDetail userDetail = new UserDetail();

                String line = scanner.nextLine();
                List<String> fields = List.of(line.split(fieldsSeparator));
                // System.out.printf("fields = %s\n", fields);
                for (String field : fields) {
                    // Process the field
                    List<String> fieldKeyValue = List.of(field.split(keyValueSeparator));
                    String key = fieldKeyValue.get(0).trim();
                    String value = fieldKeyValue.get(1).trim();
                    // System.out.printf("|%s:%s|\n", key, value);

                    switch (key) {
                        case "Login" -> userDetail.setLogin(value);
                        case "Password" -> userDetail.setPassword(value);
                        case "Salt" -> userDetail.setSalt(value);
                        case "Registration time" ->
                                userDetail.setRegistrationTime(LocalDateTime.parse(value, formatter));
                        case "Last authorization session" ->
                                userDetail.setLastAuthorizationSession(LocalDateTime.parse(value, formatter));
                        case "Access" -> {
                            ArrayList<LocalDateTime> accessDateTimes = getAccessLocalDateTimes(value, formatter);
                            userDetail.setAccess(accessDateTimes);
                        }
                    }
                }
                userDetailList.add(userDetail);

            }
        } catch (FileNotFoundException e) {
            System.out.println("No file found: " + "userData.txt");
        }

        // System.out.println(userDetailList);
        return userDetailList;
    }

    private static ArrayList<LocalDateTime> getAccessLocalDateTimes(String value, DateTimeFormatter formatter) {
        if (Objects.equals(value.trim(), "[]")) {
            return new ArrayList<LocalDateTime>();
        }

        ArrayList<LocalDateTime> accessDateTimes = new ArrayList<LocalDateTime>();
        String valueSubstr = value.substring(1, value.length() - 1);
        List<String> unsuccessfulAccesses = List.of(valueSubstr.split(","));

//        if (unsuccessfulAccesses.size() == 1) {
//            LocalDateTime accessDateTime = LocalDateTime.parse(unsuccessfulAccesses.get(0), formatter);
//            accessDateTimes.add(accessDateTime);
//            return accessDateTimes;
//        }

        for (String access : unsuccessfulAccesses) {
            LocalDateTime accessDateTime = LocalDateTime.parse(access.split(" - ")[1].trim(), formatter);
            accessDateTimes.add(accessDateTime);
        }
        return accessDateTimes;
    }

    static void addUserDetailToFile(String username, String password, String filePath) throws IOException {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

        LocalDateTime currentDateTime = LocalDateTime.now();
        String formattedDateTime = currentDateTime.format(formatter);
        byte[] saltBytes = generateSalt();

        String hashPassword = hashPassword(password, saltBytes);
        String salt = Base64.getEncoder().encodeToString(saltBytes);
        String access = "[]";

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath, true))) {

            String line = "Login: " + username.trim() +
                    "| Password: " + hashPassword +
                    "| Salt: " + salt +
                    "| Registration time: " + formattedDateTime +
                    "| Last authorization session: " + formattedDateTime +
                    "| Access: " + access;

            writer.write(line);
            writer.newLine(); // Add a newline after the line
        }
    }

    static void writeUserDetailListToFile(List<UserDetail> userDetailList, String filePath) throws IOException {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath, false))) {

            for (UserDetail user : userDetailList) {
                String line = "Login: " + user.getLogin() +
                        "| Password: " + user.getPassword() +
                        "| Salt: " + user.getSalt() +
                        "| Registration time: " + user.getRegistrationTime().format(formatter) +
                        "| Last authorization session: " + user.getLastAuthorizationSession().format(formatter) +
                        "| Access: " + setAccessLocalDateTimeToString(user.getAccess(), formatter);

                writer.write(line);
                writer.newLine();
            }

        }
    }

    static List<String> setAccessLocalDateTimeToString(List<LocalDateTime> accesses, DateTimeFormatter formatter) {
        List<String> accessesString = new ArrayList<>();
        for (LocalDateTime access: accesses) {
            accessesString.add("Unsuccessful access attempt - " + access.format(formatter));
        }
        return accessesString;
    }
}
