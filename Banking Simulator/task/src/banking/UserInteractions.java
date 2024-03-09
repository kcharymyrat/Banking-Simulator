package banking;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;
import java.net.http.HttpResponse;

import static banking.ExchangeRates.*;
import static banking.Helpers.*;
import static banking.PasswordUtils.hashPassword;
import static banking.UserList.*;
import static banking.Validators.isValidPassword;
import static banking.Validators.isValidPhoneNumber;

public class UserInteractions {

    static HttpResponse<String> response = getExchangeResponse();
    static List<Rate> rateList = parseResponse(response);

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

            Optional<UserDetail> userDetailOptional= userDetailList.stream()
                    .filter(userDetail -> Objects.equals(userDetail.getLogin(), loginFinish))
                    .findFirst();
            String userDetailLogin = userDetailOptional.map(UserDetail::getLogin).orElse(null);

            if (userDetailLogin == null) {
                System.out.println("The entered password does not match the login or the user does not exist.");
            }


            if (login.equalsIgnoreCase(loginFinish) && password.equalsIgnoreCase(passwordFinish)) {
                successAuthorizationRandomText();

                System.out.println("Menu");
                System.out.println("1. Exchange Rate, 2. Logout");
                menuAfterSuccessLogin(scanner);
                break;
            } else if (login.equalsIgnoreCase(loginFinish) && !password.equalsIgnoreCase(passwordFinish)) {
                  System.out.println("The entered password does not match the login or the user does not exist.");

                  LocalDateTime currentDateTime = LocalDateTime.now();
                  UserDetail userDetail = userDetailOptional.get();
                  userDetail.setLastAuthorizationSession(currentDateTime);
                  userDetail.addToAccess(currentDateTime);
                  writeUserDetailListToFile(userDetailList, filePath);

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

            System.out.println("Password:");
            String passwordInput = getInput(scanner);

            Optional<UserDetail> userDetailOptional= userDetailList.stream()
                    .filter(userDetail -> Objects.equals(userDetail.getLogin(), loginInput))
                    .findFirst();
            String userDetailLogin = userDetailOptional.map(UserDetail::getLogin).orElse(null);

            if (userDetailLogin == null) {
                System.out.println("The entered password does not match the login or the user does not exist.");
                continue;
            }

            String userDetailPassword = userDetailOptional.map(UserDetail::getPassword).orElse(null);
            String userDetailSalt = userDetailOptional.map(UserDetail::getSalt).orElse(null);
            byte[] saltBytes = Base64.getDecoder().decode(userDetailSalt);
            String hashOfPasswordInput = hashPassword(passwordInput, saltBytes);

            if (Objects.equals(userDetailLogin, loginInput) && !Objects.equals(userDetailPassword, hashOfPasswordInput)) {
                System.out.println("The entered password does not match the login or the user does not exist.");

                LocalDateTime currentDateTime = LocalDateTime.now();
                UserDetail userDetail = userDetailOptional.get();
                userDetail.setLastAuthorizationSession(currentDateTime);
                userDetail.addToAccess(currentDateTime);
                writeUserDetailListToFile(userDetailList, filePath);

            } else if (!Objects.equals(userDetailLogin, loginInput) || !Objects.equals(userDetailPassword, hashOfPasswordInput)) {
                System.out.println("The entered password does not match the login or the user does not exist.");
            } else {
                break;
            }
        }

        successAuthorizationRandomText();

        System.out.println("Menu");
        System.out.println("1. Exchange Rate, 2. Logout");
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

        String choice = getInput(scanner);
        if (Objects.equals("1", choice)) {
            System.out.println();
            boolean backToMainMenu = false;
            System.out.println("Exchange rates");
            while (true) {
                boolean isGoBack = exchangeRateResult(scanner, rateList);
                if (isGoBack) {
                    backToMainMenu = true;
                    break;
                }
                boolean isTryAnotherCurrency = tryAnotherCurrency(scanner);
                if (!isTryAnotherCurrency) {
                    break;
                }
            }

            if (backToMainMenu) {
                System.out.println("Menu");
                System.out.println("1. Exchange Rate, 2. Logout");
                menuAfterSuccessLogin(scanner);
            }

        }else if (Objects.equals("2", choice)) {
            System.out.println("Goodbye");
        } else {
            System.out.println("Invalid choice. Please enter a valid option number '1' or '2':");
            menuAfterSuccessLogin(scanner);
        }
    }

    static boolean exchangeRateResult(Scanner scanner, List<Rate> rateList) {
        boolean isGoBack = false;

        Rate rate = null;
        boolean exitToMenu = false;

        System.out.println("1. EUR, 2. GBP, 3. UAH, 4. CNY, 5. Back");

        do {
            String currencyChoice = getInput(scanner);

            switch (currencyChoice) {
                case "1":
                    rate = getRate(rateList, "EUR");
                    exitToMenu = true;
                    break;
                case "2":
                    rate = getRate(rateList, "GBP");
                    exitToMenu = true;
                    break;
                case "3":
                    rate = getRate(rateList, "UAH");
                    exitToMenu = true;
                    break;
                case "4":
                    rate = getRate(rateList, "CNY");
                    exitToMenu = true;
                    break;
                case "5":
                    exitToMenu = true;
                    isGoBack = true;
                    break;
                default:
                    System.out.println("Incorrect currency code, try again.");
                    System.out.println("(1. EUR, 2. GBP, 3. UAH, 4. CNY, or 5. Back):");
            }
        } while (!exitToMenu);

        if (rate != null) {
            String message = String.format(
                    "Currency exchange: USD to %s exchange rate: %s\n", rate.getBase(), rate.getUsd()
            );
            System.out.println(message);
        }

        return isGoBack;
    }

    static boolean tryAnotherCurrency(Scanner scanner) {
        System.out.println("Would you like to choose another currency? (Y/N)");

        while (true) {
            String yOrN = getInput(scanner);
            if (Objects.equals(yOrN.toUpperCase(), "Y")) {
                // 1. EUR, 2. GBP, 3. UAH, 4. CNY, 5. Back
                return true;
            } else if (Objects.equals(yOrN.toUpperCase(), "N")) {
                // return to the main menu
                return false;
            } else {
                System.out.println("Invalid input! (Y/N):");
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