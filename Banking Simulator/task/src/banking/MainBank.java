package banking;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Scanner;

import static banking.Helpers.*;
import static banking.UserInteractions.*;
import static banking.UserList.getUserDetailList;

public class MainBank {
    static List<String> list = new ArrayList<>();
    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) throws IOException {
        // Path currentPath = Paths.get("");
        //System.out.println("Current Path: " + ((Path) currentPath).toAbsolutePath());
        // Current Path: D:\JetBrainsWork\Banking Simulator\Banking Simulator\task
        // final String filePath = ".\\Banking Simulator\\task\\userData.txt";
        // System.out.println(userDetialList);

        final String filePath = ".\\userData.txt";
        List<UserDetail> userDetialList = getUserDetailList(filePath);

        System.out.println("Would you like to login or register?");
        System.out.print("1. Login, 2. Register: ");


        System.out.println();
        while (true) {
            String loginOrRegister = getInput(scanner).trim();
            if (Objects.equals(loginOrRegister, "2")) {
                userDetialList = getUserDetailList(filePath);
                registrationChoiceMenu(scanner, userDetialList, filePath);
                return;
            } else if (Objects.equals(loginOrRegister, "1")) {
                userDetialList = getUserDetailList(filePath);
                loginChoice(scanner, userDetialList, filePath);
                return;
            }
            System.out.println("Invalid input, try again '1 or 2':");
        }

    }












    //    private stageTwo() {
//        String login = "";
//        String password = "";
//
//        System.out.println("Registration");
//
//        login = getLoginInputRecursive(usernames);
//        password = getPasswordInputRecursive();
//
//        addUsernameToFile(login, password, filePath);
//        usernames = getUsernames(filePath);
//
//        System.out.println();
//        System.out.println("Enter the data again to complete the registration");
//
//        while (true) {
//            System.out.println("Login:");
//            String loginTrial = cleanLogin(getInput());
//
//            System.out.println("Password:");
//            String passwordTrial = getInput();
//
//            if (!login.equalsIgnoreCase(loginTrial) && !password.equalsIgnoreCase(passwordTrial)) {
//                System.out.println();
//                System.out.println("Login and password don't match.");
//            } else if (!login.equalsIgnoreCase(loginTrial)) {
//                System.out.println();
//                System.out.println("Login doesn't match.");
//            } else if (!password.equalsIgnoreCase(passwordTrial)) {
//                System.out.println();
//                System.out.println("Passwords don't match");
//            }
//
//            if (login.equalsIgnoreCase(loginTrial) && password.equalsIgnoreCase(passwordTrial)) {
//                break;
//            }
//        }
//
//        System.out.println();
//        System.out.println("Now you can log in for finishing the registration.");
//        System.out.println("Login:");
//        String loginFinish = cleanLogin(getInput());
//
//        System.out.println("Password:");
//        String passwordFinish = getInput();
//
//        if (login.equalsIgnoreCase(loginFinish) && password.equalsIgnoreCase(passwordFinish)) {
//            System.out.println("Authorization successful");
//            System.out.println("Congratulations on your successful registration!");
//        } else {
//            System.out.println("Authorization failed");
//        }
//
//        scanner.close();
//    }
//
}
