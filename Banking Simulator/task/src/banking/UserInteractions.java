package banking;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static banking.Helpers.*;
import static banking.PasswordUtils.hashPassword;
import static banking.UserList.addUserDetailToFile;
import static banking.UserList.getUserDetailList;
import static banking.Validators.isValidPassword;
import static banking.Validators.isValidPhoneNumber;

public class UserInteractions {

    private static final String[] loginGreetings = {
            "Welcome to your personal banking",
            "Welcome back!",
            "We've been waiting for you!",
            "Good to see you!",
            "ZZzzzzZ... ERROR... It's a joke, it's ok, welcome back!"
    };

    static void registrationChoiceMenu(Scanner scanner, List<UserDetail> userDetailList, String filePath) throws IOException {
        String login = "";
        String password = "";

        System.out.println("Registration");
        List<String> usernames = userDetailList.stream().map(UserDetail::getLogin).collect(Collectors.toList());
        login = getLoginInputRecursive(usernames, scanner);
        password = getPasswordInputRecursive(scanner);

        addUserDetailToFile(login, password, filePath);

        userDetailList = getUserDetailList(filePath);
        usernames = userDetailList.stream().map(UserDetail::getLogin).collect(Collectors.toList());
        System.out.println();

        System.out.println("Enter the data again to complete the registration");
        while (true) {
            System.out.println("Login:");
            String loginTrial = cleanLogin(getInput(scanner));

            System.out.println("Password:");
            String passwordTrial = getInput(scanner);

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
        System.out.println("Congratulations on your successful registration!");
        System.out.println("Now you can log in!");
        System.out.println();

        while (true) {
            System.out.println("Authorization");
            System.out.println("Login:");
            String loginFinish = cleanLogin(getInput(scanner));

            System.out.println("Password:");
            String passwordFinish = getInput(scanner);

            if (login.equalsIgnoreCase(loginFinish) && password.equalsIgnoreCase(passwordFinish)) {
                successAuthorizationRandomText();
                menuAfterSuccessLogin(scanner);
                break;
            } else {
                System.out.println("The entered password does not match the login or the user does not exist.");
            }
        }
    }

    static void loginChoice(Scanner scanner, List<UserDetail> userDetailList, String filePath) throws IOException {

        while (true) {
            System.out.println("Authorization");
            System.out.println("Login:");
            String loginInput = cleanLogin(getInput(scanner));

            Optional<UserDetail> userDetailOptional= userDetailList.stream()
                    .filter(userDetail -> Objects.equals(userDetail.getLogin(), loginInput))
                    .findFirst();
            String userDetailLogin = userDetailOptional.map(UserDetail::getLogin).orElse(null);


            System.out.println("Password:");
            String passwordInput = getInput(scanner);
            String userDetailPassword = userDetailOptional.map(UserDetail::getPassword).orElse(null);
            String userDetailSalt = userDetailOptional.map(UserDetail::getSalt).orElse(null);
            byte[] saltBytes = Base64.getDecoder().decode(userDetailSalt);
            String hashOfPasswordInput = hashPassword(passwordInput, saltBytes);

            if (!Objects.equals(userDetailLogin, loginInput) || !Objects.equals(userDetailPassword, hashOfPasswordInput)) {
                System.out.println("The entered password does not match the login or the user does not exist.");
            } else {
                break;
            }
        }

        successAuthorizationRandomText();
        menuAfterSuccessLogin(scanner);
    }

    static void successAuthorizationRandomText() {
        System.out.println("Authorization successful");
        System.out.println();
        int randomIndex = getRandomIndex(loginGreetings.length);
        String randomGreeting = loginGreetings[randomIndex];
        System.out.println(randomGreeting);
    }

    static void menuAfterSuccessLogin(Scanner scanner) {
        System.out.println("Menu");
        System.out.println("1. Logout");
        while (true) {
            String choice = getInput(scanner);
            if (Objects.equals("1", choice)) {
                System.out.println("Goodbye");
                return;
            } else {
                System.out.println("Invalid choice. Please enter a valid option number '1':");
            }
        }
    }

    static String getLoginInputRecursive(List<String> usernames, Scanner scanner) {
        System.out.println("Login:");
        String login = cleanLogin(getInput(scanner));

        if (!isValidPhoneNumber(login)) {
            System.out.println("Wrong login format, try again");
            return getLoginInputRecursive(usernames, scanner);
        }

        if (usernames.contains(login) || usernames.contains("+" + login)) {
            System.out.println("Login is already taken, try another login");
            return getLoginInputRecursive(usernames, scanner);
        }

        return login;
    }

    static String getPasswordInputRecursive(Scanner scanner) {
        System.out.println("Password:");
        String password = getInput(scanner).trim();
        if (!isValidPassword(password)){
            System.out.println("Wrong password format, try again");
            return getPasswordInputRecursive(scanner);
        }
        return password;
    }
}
