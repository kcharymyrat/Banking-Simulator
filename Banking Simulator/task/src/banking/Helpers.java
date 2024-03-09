package banking;

import java.util.Random;
import java.util.Scanner;

public class Helpers {

    static String getInput(Scanner scanner) {
        return scanner.nextLine().strip().trim();
    }

    public static int getRandomIndex(int length) {
        Random random = new Random();
        return random.nextInt(length);
    }


    static String cleanLogin(String login) {
        var loginStringBuilder = new StringBuilder();

        for (char ch : login.toCharArray()) {
            String chStr = String.valueOf(ch);
            if (chStr.matches("\\d")) {
                loginStringBuilder.append(chStr);
            }
        }
        return loginStringBuilder.toString();
    }
}
