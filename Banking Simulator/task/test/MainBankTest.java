import org.hyperskill.hstest.dynamic.DynamicTest;
import org.hyperskill.hstest.exception.outcomes.WrongAnswer;
import org.hyperskill.hstest.stage.StageTest;
import org.hyperskill.hstest.testcase.CheckResult;
import org.hyperskill.hstest.testing.TestedProgram;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.regex.Pattern;

import static org.hyperskill.hstest.testing.expect.Expectation.expect;

public class MainBankTest extends StageTest<String> {
    private final File file = new File("userData.txt");
    private final HashMap<String, String> USERS = new HashMap<>();
    private TestedProgram main;

    @DynamicTest
    CheckResult  test1() {
        String login = generatePhone(true);
        String password = generatePassword(true);
        startInit();

        try {
            Files.writeString(file.toPath(), "");
        } catch (IOException e) {
            throw new WrongAnswer("Before testing file 'userData.txt' must be empty! Failed to access file.");
        }
//      for line equal to Password
        String output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
//      for line equal to "reg again and log in"
        output = main.execute(password);
        majorTestingMethod("Enter the data again to complete the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
//      for line equal to Password
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
//      for line equal congratulations, now you can and log in
        output = main.execute(password);

        majorTestingMethod("Now you can log in for finishing the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
//      for line equal to Password
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
//      for line equal failed
        output = main.execute(password);
        majorTestingMethod("Authorization successful.", 2, 1, output);
        majorTestingMethod("Congratulations on your successful registration!", 2, 2, output);
//      if main is finished
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        USERS.put(login, password);
        return CheckResult.correct();
    }

    @DynamicTest
    CheckResult test2() {
        String login = generatePhone(true);
        String password = generatePassword(true);
        startInit();
        String output;
//      for line equal to Password
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
//      for line equal to "reg again and log in"
        output = main.execute(password);
        majorTestingMethod("Enter the data again to complete the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
//      for line equal to Password
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
//      for line equal congratulations, now you can and log in
        output = main.execute(password);

        majorTestingMethod("Now you can log in for finishing the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
//      for line equal to Password
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
//      for line equal failed
        output = main.execute(password.substring(1));
        USERS.put(login, password);
        majorTestingMethod("Authorization failed.", 1, 1, output);
//      if main is finished
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        return CheckResult.correct();
    }

    @DynamicTest
    CheckResult test3() {
        String login = generatePhone(true);
        String password = generatePassword(true);
        startInit();
        String output;
//      for line equal to Password
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
//      for line equal to "reg again and log in"
        output = main.execute(password);
        majorTestingMethod("Enter the data again to complete the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        //wrong login
        output = main.execute("12222624362");
        majorTestingMethod("Password:", 1, 1, output);

        //Login and password don't match.
        output = main.execute(password.substring(1));
        majorTestingMethod("Login and password don't match.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        output = main.execute("12222624362");
        majorTestingMethod("Password:", 1, 1, output);

        output = main.execute(password);
        majorTestingMethod("Login doesn't match.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);

        output = main.execute("MEGAPASSSSSSSSSSSSSWORD");
        majorTestingMethod("Password doesn't match.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
//      for line equal congratulations, now you can and log in
        output = main.execute(password);

        majorTestingMethod("Now you can log in for finishing the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

//      for line equal to Password
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
//      for line equal to successful reg
        output = main.execute(password);
        majorTestingMethod("Authorization successful.", 2, 1, output);
        majorTestingMethod("Congratulations on your successful registration!", 2, 2, output);
        USERS.put(login, password);
//      if main is finished
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        return CheckResult.correct();
    }

    @DynamicTest
    CheckResult test4() {
        startInit();
        return CheckResult.correct();
    }

    @DynamicTest(repeat = 10)
    CheckResult test5() {
        startInit();
        String output;
        var login = generatePhone(true);
        var password = generatePassword(true);
        USERS.put(login, password);
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
//      for line equal to Password
        output = main.execute(generatePassword(false));
        majorTestingMethod("Wrong password format, try again", 2, 1, output);
        majorTestingMethod("Password:", 2, 2, output);

        output = main.execute(password);
        majorTestingMethod("Enter the data again to complete the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
        output = main.execute(password);

        majorTestingMethod("Now you can log in for finishing the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

//      for line equal to Password
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
//      for line equal to successful reg
        output = main.execute(password);
        majorTestingMethod("Authorization successful.", 2, 1, output);
        majorTestingMethod("Congratulations on your successful registration!", 2, 2, output);
        USERS.put(login, password);
//      if main is finished
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        return CheckResult.correct();
    }

    @DynamicTest(repeat = 17)
    CheckResult test6() {
        String login = generatePhone(true);
        String password = generatePassword(true);
        USERS.put(login, password);
        startInit();
        String output;
//      for line equal to Password
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
//      for line equal to "reg again and log in"
        output = main.execute(password);
        majorTestingMethod("Enter the data again to complete the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
//      for line equal to Password
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
//      for line equal congratulations, now you can and log in
        output = main.execute(password);

        majorTestingMethod("Now you can log in for finishing the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
//      for line equal to Password
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
//      for line equal failed
        output = main.execute(password);

        majorTestingMethod("Authorization successful.", 2, 1, output);
        majorTestingMethod("Congratulations on your successful registration!", 2, 2, output);

//      if main is finished
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        return CheckResult.correct();
    }

    @DynamicTest(repeat = 3)
    CheckResult test7() {
        startInit();
        String output;

        for (int i = 0; i < randomize(10); i++) {
            output = main.execute(generatePhone(false));
            majorTestingMethod("Wrong login format, try again", 2, 1, output);
            majorTestingMethod("Login:", 2, 2, output);
        }
       String login = generatePhone(true);
       String password = generatePassword(true);

        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);

        output = main.execute(password);
        majorTestingMethod("Enter the data again to complete the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);

        output = main.execute(password);
        majorTestingMethod("Now you can log in for finishing the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
        output = main.execute(password);
        majorTestingMethod("Authorization successful.", 2, 1, output);
        majorTestingMethod("Congratulations on your successful registration!", 2, 2, output);
        USERS.put(login, password);
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        return CheckResult.correct();
    }

    @DynamicTest(repeat = 3)
    CheckResult test8() {
        startInit();
        String output;
        var login = generatePhone(true);
        var password = generatePassword(true);

        for (int i = 0; i < randomize(3); i++) {
            output = main.execute(USERS.keySet().stream().toList().get(randomize(USERS.size())));
            majorTestingMethod("Login is already taken, try another login.", 2, 1, output);
            majorTestingMethod("Login:", 2, 2, output);
        }
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
//      for line equal to "reg again and log in"
        output = main.execute(password);
        majorTestingMethod("Enter the data again to complete the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
//      for line equal to Password
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
//      for line equal congratulations, now you can and log in
        output = main.execute(password);
        majorTestingMethod("Now you can log in for finishing the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

//      for line equal to Password
        var tmpLogin = USERS.keySet().stream().toList().get(randomize(USERS.size()));
        USERS.put(login, password);
        output = main.execute(tmpLogin);
        majorTestingMethod("Password:", 1, 1, output);
//      for line equal failed
        output = main.execute(password);
        majorTestingMethod("Authorization failed", 1, 1, output);
//      if main is finished
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }

        return CheckResult.correct();
    }

    @DynamicTest(repeat = 3)
    CheckResult test9() {
        startInit();
        String output;
        String login = USERS.keySet().stream().toList().get(randomize(USERS.size()));
        String password = USERS.get(login);

        List<String> userData;
        try {
            userData = Files.readAllLines(Path.of(file.getPath()));
        } catch (IOException e) {
            throw new WrongAnswer("Unable to read userData.txt file or file was not found: " + e.getMessage());
        }

        var testingUserSections = getStrings(userData, login, password);

        String TIMEREGEX = "\\d{1,4}[/\\\\\\s:\\-]\\d{1,2}[/\\\\\\s:\\-]\\d{1,4} \\d{1,2}[\\s:\\-]\\d{1,2}([\\s:\\-]\\d{1,2})?$";
        if (!testingUserSections[2].substring(19).matches(TIMEREGEX)) {
            throw new WrongAnswer("The Registration time section was not saved in the database, or it was not saved correctly.");
        }
        var tmpLogin = generatePhone(true);
        var tmpPassword = generatePassword(true);

        output = main.execute(tmpLogin);
        majorTestingMethod("Password:", 1, 1, output);
        output = main.execute(tmpPassword);
        majorTestingMethod("Enter the data again to complete the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        output = main.execute(tmpLogin);
        majorTestingMethod("Password:", 1, 1, output);
        output = main.execute(tmpPassword);

        majorTestingMethod("Now you can log in for finishing the registration.", 2, 1, output);

        majorTestingMethod("Login:", 2, 2, output);
        output = main.execute(tmpLogin);
        majorTestingMethod("Password:", 1, 1, output);

        output = main.execute(tmpPassword);
        majorTestingMethod("Authorization successful.", 2, 1, output);
        majorTestingMethod("Congratulations on your successful registration!", 2, 2, output);
        USERS.put(tmpLogin, tmpPassword);

        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        return CheckResult.correct();
    }

    private String[] getStrings(List<String> userData, String login, String password) {
        if (userData.size() != USERS.size()) {
            throw new WrongAnswer("""
                    The userData.txt file should contain data about users who were registered during the tests.
                    User data must start on a new line.
                    Example:
                    Login: +(1)-321-123-1234, Password: TestPassword123!, Registration time: 2023-07-14 11:17
                    Login: 13211231234, Password: TestPassword123!, Registration time: 2023-07-14 11:17
                    Login: 1-321-123-1234, Password: TestPassword123!, Registration time: 2023-07-14 11:17
                    ...all subsequent entries.
                    """);
        }

        var testingUserSections = getTestingUserSections(userData, login);
        if (!testingUserSections[1].replace("Password: ", "").equals(password)) {
            throw new WrongAnswer("The password was not saved in the database, or it was not saved correctly.");
        }
        return testingUserSections;
    }

    private static String[] getTestingUserSections(List<String> userData, String login) {
        String testingUser = null;
        for (var user : userData) {
            String[] line = getLine(user);
            if (line[0].replaceAll("\\D", "").equals(login.replaceAll("\\D", ""))) {
                testingUser = user;
                break;
            }
        }

        if (testingUser == null) {
            throw new WrongAnswer("The user being tested does not exist in the database,but was registered during the tests." + " Login: " + login);
        }
        var testingUserSections = testingUser.split(", ");

        if (!testingUserSections[1].startsWith("Password:")) {
            throw new WrongAnswer("The 'Password' section should start like this - Password: \n" + "Your line contains- " + testingUserSections[1]);
        }
        return testingUserSections;
    }

    private static String[] getLine(String user) {
        String[] line = user.split(", ");
        if (line.length != 3) {
            throw new WrongAnswer("The userData.txt The file must contain user data, each of which consists of 3 sections,\n" + " the sections must be separated by this character - ',' Each new user starts on a new line.");
        }
//          'Login' section testing
        if (!line[0].startsWith("Login:")) {
            throw new WrongAnswer("The string containing user data must start with 'Login:' but your string output equals - " + line[0]);
        }
        return line;
    }

    private void startInit() {
        main = new TestedProgram();
        String output = main.start();

        majorTestingMethod("Registration", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
    }


    private void majorTestingMethod(String correctOutput, int correctNumberOfLines, int testableOutputTextOnLineNumbered, String output) {
        String[] regexes = getRegexes();

        var outputLines = expect(output).toContain(correctNumberOfLines).lines();

        String[] executeText = outputLines.toArray(new String[0]);

        String check = executeText[testableOutputTextOnLineNumbered - 1].trim();// If outputLines does not match the expected number of lines, the test will not reach [outputTextInLineNumber - 1], now it's safe.

        for (String regex : regexes) {
            var pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
            if (pattern.matcher(correctOutput).find()) {
                if (pattern.matcher(check).find()) {
                    return;
                }
            }
        }
        throw new WrongAnswer("Your program should print '" + correctOutput + "' but it printed '" + check + "'");
    }

    private static String[] getRegexes() {
        String looseTestes = "[!.]?$";
        String looseTestes2 = "(don['`]?t)|(doesn['`]?t)";
        return new String[]{"^enter[a-z\\s]+?again[a-z\\s]+?complete[a-z\\s]+?registrations?" + looseTestes //0
                , "^passwords? " + looseTestes2 + " match" + looseTestes //1
                , "^logins? " + looseTestes2 + " match" + looseTestes //2
                , "^logins? and passwords? " + looseTestes2 + " match" + looseTestes,   //3
                "^congratulations? on your? successful registrations?" + looseTestes, //4
                "^login:$", //5
                "^password:$", //6

                "^authorization successful" + looseTestes, //7
                "^authorization failed" + looseTestes, //8
                "^wrong login format,? try again" + looseTestes, //9
                "^wrong password format,? try again" + looseTestes, //10
                "^login is already taken,? try (another login)?(again)?" + looseTestes, //11
                "^now you can log\\s?in for finishing the registration" + looseTestes, //12
                "^registration\\.?$" //13
        };
    }

    private String generatePhone(boolean isCheck) {
        String login = "";
        while (true) {
            if (isCheck) {

                int rand = randomize(3);
                switch (rand) {
                    case 0 ->
                            login = String.format("+(1)-%s-%s-%s", generateRandomDigits(3), generateRandomDigits(3), generateRandomDigits(4));
                    case 1 ->
                            login = String.format("(1) %s %s %s", generateRandomDigits(3), generateRandomDigits(3), generateRandomDigits(4));
                    case 2 ->
                            login = String.format("1%s%s%s", generateRandomDigits(3), generateRandomDigits(3), generateRandomDigits(4));
                    default -> {
                    }
                }
                if (validatePhone(login) && !USERS.containsKey(login)) {
                    break;
                }
            } else {
                login = String.format("+(%s)-%s-%s-%s", generateRandomAnyCase(2), generateRandomAnyCase(3), generateRandomAnyCase(3), generateRandomAnyCase(4));
                if (!validatePhone(login)) {
                    break;
                }

            }

        }
        return login;
    }

    private String generateRandomDigits(int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(randomize(10));
        }
        return sb.toString();
    }

    private String generateRandomAnyCase(int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(forAnyCase[randomize(forAnyCase.length)]);
        }
        return sb.toString();
    }

    private boolean validatePhone(String phoneNumber) {
        // Checking all requirements
        Pattern pattern = Pattern.compile("^\\+?\\(?1\\)?[-\\s]?\\d{3}[-\\s]?\\d{3}[-\\s]?\\d{4}$");
        boolean isMatch = pattern.matcher(phoneNumber).matches();
        // Checking the length
        phoneNumber = phoneNumber.replaceAll("\\D", "");
        boolean lengthCase = phoneNumber.length() == 11;
        // result
        return isMatch && lengthCase;
    }

    private String generatePassword(boolean isCheck) {
        Random random = new Random();
        StringBuilder passwordBuilder = new StringBuilder();
        int length = randomize(19) + 7;
        String output;
        while (true) {
            for (int i = 0; i < length; i++) {
                var forLoginNReg = forAnyCase[random.nextInt(forAnyCase.length)];
                passwordBuilder.append(forLoginNReg);
            }
            output = passwordBuilder.toString();
            if (isCheck) {
                if (validatePassword(output)) {
                    break;
                }
            } else {
                if (!validatePassword(output)) {
                    break;
                }
            }
            passwordBuilder.setLength(0);
        }
        return output;
    }

    private final Object[] forAnyCase = {"!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "=", "+", "[", "]", "{", "}", "|", "\\", ";", ":", "'", "\"", ",", ".", "<", ">", "/", "?", "`", "~", " ", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"};

    private boolean validatePassword(String password) {
        return password.length() >= 6 && password.length() <= 28 // Valid password length
               && password.replaceAll("[a-zA-Z\\d!@#$%\\s]", "").isEmpty() // Valid characters
               && password.matches(".*[A-Z].*") // At least one capital letter
               && password.matches(".*[a-z].*") // At least one lowercase letter
               && password.matches(".*\\d.*") // At least one digit
               && !password.matches("^\\s.*|^.*\\s$"); // Space start or end
    }

    private int randomize(int bound) {
        return new Random().nextInt(bound);
    }
}