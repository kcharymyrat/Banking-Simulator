package banking;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Scanner;

import static banking.Helpers.getInput;
import static banking.UserInteractions.loginChoice;
import static banking.UserInteractions.registrationChoiceMenu;
import static banking.UserList.getUserDetailList;

public class MainBank {
    static List<String> list = new ArrayList<>();
    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) throws IOException {
        // Path currentPath = Paths.get("");
        // System.out.println("Current Path: " + ((Path) currentPath).toAbsolutePath());
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

}
