package banking;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class MainBank {
    static List<String> list = new ArrayList<>();
    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {

        System.out.println("Username:");
        list.add(getInput());

        System.out.println("Password:");
        list.add(getInput());

        System.out.println();
        System.out.println("Enter the data again to complete the registration");

        System.out.println("Username:");
        String login = getInput();

        System.out.println("Password:");
        String pass = getInput();

        var name = list.get(0).equals(login);
        var pas = list.get(1).equals(pass);

        if (name && pas) {
            System.out.println(System.lineSeparator() + "Congratulations on your successful registration!");
        } else if (!name && !pas) {
            System.out.println("Username and password don't match.");
        } else {
            if (!pas) {
                System.out.println("Passwords don't match.");
            } else {
                System.out.println("Username doesn't match.");
            }
        }
        scanner.close();
    }

    private static String getInput() {
        return scanner.nextLine().strip().trim();
    }
}
