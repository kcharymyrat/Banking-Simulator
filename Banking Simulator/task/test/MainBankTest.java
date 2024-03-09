import org.hyperskill.hstest.dynamic.DynamicTest;
import org.hyperskill.hstest.exception.outcomes.WrongAnswer;
import org.hyperskill.hstest.stage.StageTest;
import org.hyperskill.hstest.testcase.CheckResult;
import org.hyperskill.hstest.testing.TestedProgram;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.hyperskill.hstest.testing.expect.Expectation.expect;

public class MainBankTest extends StageTest<String> {
    private final File file = new File("userData.txt");
    private TestedProgram main;


    @DynamicTest
//(feedback = "Complete registrations")
    CheckResult test1() {
        String login = generatePhone(true);
        String password = generatePassword(true);
        USERS.put(login, password);
        startInit();
        String output;
        try {
            Files.writeString(file.toPath(), "");
        } catch (IOException e) {
            throw new WrongAnswer("Before testing file 'userData.txt' must be empty! Failed to access file.");
        }
//      for line equal to Password
        output = main.execute("2");
        majorTestingMethod("Registration", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

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
        majorTestingMethod("Congratulations on your successful registration!", 5, 1, output);
        majorTestingMethod("Now you can log in!", 5, 2, output);

        majorTestingMethod("Authorization", 5, 4, output);
        majorTestingMethod("Login:", 5, 5, output);
        authorize(login, password);

        return CheckResult.correct();
    }

    @DynamicTest
//(feedback = "Testing '1 or 2' when choosing Authorization or Registration. Finished testing, completing registration +1-2345678901")
    CheckResult test2() {

        startInit();
        String output;
        for (int i = 0; i < 8; i++) {
            output = main.execute("");
            majorTestingMethod("Invalid input, try again '1 or 2':", 1, 1, output);
            output = main.execute(Arrays.stream(forAnyCase).toList().get(randomize(forAnyCase.length - 1)).toString().replaceAll("[1-2]", ""));
            majorTestingMethod("Invalid input, try again '1 or 2':", 1, 1, output);
        }
        output = main.execute("1");
        majorTestingMethod("Authorization", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
        var p = USERS.keySet().stream().toList().get(0);

        output = main.execute(p);
        majorTestingMethod("Password:", 1, 1, output);

        output = main.execute(USERS.get(p));

        majorTestingMethod("Authorization successful.", 5, 1, output);
        var splits = output.split("\\n");
        if (splits[2].length() > 60) {
            throw new WrongAnswer("Your creativity '" + splits[2].length() + "' - exceeds the 60 character limit, try shortening the message a bit");
        }
        majorTestingMethod("Menu", 5, 4, output);
        majorTestingMethod("1. Logout", 5, 5, output);
        for (int j = 0; j < 8; j++) {
            output = main.execute(Arrays.stream(forAnyCase).toList().get(randomize(forAnyCase.length - 1)).toString().replaceAll("1", ""));
            majorTestingMethod("Invalid choice. Please enter a valid option number '1':", 1, 1, output);
        }
        output = main.execute("1");
        majorTestingMethod("Goodbye", 1, 1, output);

        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }

        return CheckResult.correct();
    }

    //(feedback = "Testing regular registration")
    @DynamicTest
    CheckResult test3() {
        startInit();
        String output = main.execute("2");
        majorTestingMethod("Registration", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        output = main.execute(USERS.keySet().stream().toList().get(randomize(USERS.size())));
        majorTestingMethod("Login is already taken, try another login.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        String login = generatePhone(true);
        String password = generatePassword(true);
        USERS.put(login, password);
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
        output = main.execute(password);
        majorTestingMethod("Enter the data again to complete the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
        output = main.execute(password);
        majorTestingMethod("Congratulations on your successful registration!", 5, 1, output);
        majorTestingMethod("Now you can log in!", 5, 2, output);
        majorTestingMethod("Authorization", 5, 4, output);
        authorize(login, password);
        return CheckResult.correct();
    }

    @DynamicTest(repeat = 5)
//(feedback = "Testing mismatching login and password")
    CheckResult test4() {
        String login = generatePhone(true);
        String password = generatePassword(true);
        USERS.put(login, password);
        var wrongLog = generatePhone(false);
        var wrongPass = generatePassword(false);
        startInit();
        String output = main.execute("2");
        majorTestingMethod("Registration", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
        output = main.execute(password);
        majorTestingMethod("Enter the data again to complete the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
        //      for line equal to Password
        output = main.execute(wrongLog);
        majorTestingMethod("Password:", 1, 1, output);
        //Login and password don't match.
        output = main.execute(wrongPass);
        majorTestingMethod("Login and password don't match.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
        output = main.execute(wrongLog);
        majorTestingMethod("Password:", 1, 1, output);
        output = main.execute(password);
        majorTestingMethod("Login doesn't match.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
        output = main.execute(wrongPass);
        majorTestingMethod("Password doesn't match.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
        //      for line equal congratulations, now you can and log in
        output = main.execute(password);
        majorTestingMethod("Congratulations on your successful registration!", 5, 1, output);
        majorTestingMethod("Now you can log in!", 5, 2, output);
        majorTestingMethod("Authorization", 5, 4, output);
        majorTestingMethod("Login:", 5, 5, output);
        for (int j = 0; j < 3; j++) {
            output = main.execute(login);
            majorTestingMethod("Password:", 1, 1, output);
            output = main.execute(wrongPass);
            majorTestingMethod("The entered password does not match the login or the user does not exist.", 3, 1, output);

            majorTestingMethod("Login:", 3, 3, output);
        }
        authorize(login, password);
        return CheckResult.correct();
    }

    @DynamicTest(repeat = 10)
//(feedback = "Testing when correct login")
    CheckResult test5() {
        startInit();
        String output = main.execute("2");
        majorTestingMethod("Registration", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        output = main.execute(generatePhone(false));
        majorTestingMethod("Wrong login format, try again", 2, 1, output);

        majorTestingMethod("Login:", 2, 2, output);
        String login = generatePhone(true);
        String password = generatePassword(true);
        USERS.put(login, password);
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
        output = main.execute(password);
        majorTestingMethod("Enter the data again to complete the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
        output = main.execute(password);
        majorTestingMethod("Congratulations on your successful registration!", 5, 1, output);
        majorTestingMethod("Now you can log in!", 5, 2, output);
        majorTestingMethod("Authorization", 5, 4, output);
        return CheckResult.correct();
    }

    @DynamicTest(repeat = 12)
//(feedback = "Testing output when correct password format")
    CheckResult test6() {
        String password = generatePassword(false);
        String login = generatePhone(true);
        startInit();
        String output = main.execute("2");
        majorTestingMethod("Registration", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);

        output = main.execute(password);
        majorTestingMethod("Wrong password format, try again", 2, 1, output);

        majorTestingMethod("Password:", 2, 2, output);


        password = generatePassword(true);
        USERS.put(login, password);
        output = main.execute(password);
        majorTestingMethod("Enter the data again to complete the registration.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
        output = main.execute(password);
        majorTestingMethod("Congratulations on your successful registration!", 5, 1, output);
        majorTestingMethod("Now you can log in!", 5, 2, output);
        majorTestingMethod("Authorization", 5, 4, output);
        return CheckResult.correct();
    }

//(feedback = "Testing output when failed authorization")

    @DynamicTest(repeat = 20)
    CheckResult test7() {

        startInit();
        String output = main.execute("1");
        majorTestingMethod("Authorization", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        var login = USERS.keySet().stream().toList().get(randomize(USERS.size()));
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
        output = main.execute(generatePassword(false));
        majorTestingMethod("The entered password does not match the login or the user does not exist.", 3, 1, output);

        majorTestingMethod("Login:", 3, 3, output);


        authorize(login, USERS.get(login));
        return CheckResult.correct();
    }
//(feedback = "Testing the output of random greeting phrases against the given parameters")

    @DynamicTest(repeat = 30)
    CheckResult test8() {
        String login = USERS.keySet().stream().toList().get(randomize(USERS.size()));
        String password = USERS.get(login);
        startInit();
        String output = main.execute("1");
        majorTestingMethod("Authorization", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
        authorize(login, password);

        return CheckResult.correct();
    }
//(feedback = "Testing userData file")


    @DynamicTest
    CheckResult test9() {
        for (var log : USERS.entrySet()) {
            startInit();
            String output = main.execute("1");
            majorTestingMethod("Authorization", 2, 1, output);
            majorTestingMethod("Login:", 2, 2, output);

            output = main.execute(log.getKey());
            majorTestingMethod("Password:", 1, 1, output);

            output = main.execute(log.getValue());
            majorTestingMethod("Authorization successful.", 5, 1, output);

            majorTestingMethod("Menu", 5, 4, output);
            majorTestingMethod("1. Logout", 5, 5, output);
            output = main.execute("1");
            majorTestingMethod("Goodbye", 1, 1, output);

            if (!main.isFinished()) {
                throw new WrongAnswer("Your program should finish");
            }
        }
        return CheckResult.correct();
    }

    @DynamicTest(repeat = 5)
    CheckResult test10() {
        var file = new File("userData.txt");

        var login = USERS.keySet().stream().toList().get(randomize(USERS.size()));
        var password = USERS.get(login);
        startInit();
        String output = main.execute("1");
        majorTestingMethod("Authorization", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
        output = main.execute("Started test file 'userData.txt'.");
        majorTestingMethod("The entered password does not match the login or the user does not exist.", 3, 1, output);

        List<String> userData;
        try {
            userData = Files.readAllLines(Path.of(file.getPath()));
        } catch (IOException e) {
            throw new WrongAnswer("Unable to read userData.txt file or file was not found: " + e.getMessage());
        }

        var testingUserSections = getStrings(userData, login);
        String savedHashedPassword = testingUserSections[1].substring(10);
        byte[] savedSalt = Base64.getDecoder().decode(testingUserSections[2].substring(6));
        if (!verifyPassword(password, savedSalt, savedHashedPassword)) {
            throw new WrongAnswer("""
                    The password and salt was not saved in the database, or it was not saved correctly.
                    Example correct password and salt:
                    Password: MuIpL4JJbjRpTGdg2oMawHWMEt91AiLxGFgoiw8yjC8=| Salt: Ypt72qwV6/5QXKcmG84WJ/dfnydrlxy1v+ajBBfKE/0=|
                    Where '|' is a delimiter.""");
        }

//          'Registration time' section testing
        String registrationTimeSection = testingUserSections[3].substring(19);

        String TIMEREGEX = "\\d{1,4}[/\\\\\\s:\\-]\\d{1,2}[/\\\\\\s:\\-]\\d{1,4} \\d{1,2}[\\s:\\-]\\d{1,2}([\\s:\\-]\\d{1,2})?$";
        if (!registrationTimeSection.matches(TIMEREGEX)) {
            throw new WrongAnswer("The Registration time section was not saved in the database, or it was not saved correctly.");
        }

//          'Last authorization session' section testing
        if (!testingUserSections[4].substring(28).matches(TIMEREGEX)) {
            throw new WrongAnswer("The 'Last authorization session' section was not saved in the database, or it was not saved correctly.");
        }

        if (testingUserSections[5].replaceAll("[^]\\[]", "").length() != 2) {
            throw new WrongAnswer("The 'Access' section must be contains char '[' and ']' inside which attempts to unsuccessfully enter the account should be recorded.");
        }

        Pattern pattern = Pattern.compile(".*\\[(.+)].*");
        Matcher matcher = pattern.matcher(testingUserSections[5]);
        int getDataBaseAccessAttemptsCountRecorded;
        if (matcher.find()) {
            getDataBaseAccessAttemptsCountRecorded = matcher.group(1).split(", ").length;
        } else {
            getDataBaseAccessAttemptsCountRecorded = 0;
        }

        if (getDataBaseAccessAttemptsCountRecorded > 3) {
            throw new WrongAnswer("The 'Access:' section should have contained one entry 'Unsuccessful access attempt - yyyy-MM-dd HH:mm' - no more than 3 entries.");
        }

        main.execute("Test passed, don't worry about next output.");
        return CheckResult.correct();
    }

    private String[] getStrings(List<String> userData, String login) {
        if (userData.size() != USERS.size()) {
            throw new WrongAnswer("""
                    The userData.txt file should contain data about users who were registered during the tests.
                    User data must start on a new line.
                    Example:
                    Login: +(1) 123 123 3333| Password: H7zhSEcK3ATrndB7gvJmd5Zbqtiwk9lrhcyeHhUEk5Y=| Salt: pTXvgvjebxPh2qLRqIdvoZuX8TxyR3u+ZEoRhFubgG8=| Registration time: 2023-06-01 17:26| Last authorization session: 2023-06-01 17:26| Access: [Unsuccessful access attempt - 2023-08-01 11:26, Unsuccessful access attempt - 2023-08-01 12:26, Unsuccessful access attempt - 2023-08-01 13:26]
                    Login: 1 342 343 5544| Password: Of9ciui/5d/Tlv94m+cVCx5wdWG1QbRqMldPRNSvnvc=| Salt: DRySPA7xv3oTxBzFDUTgzkuDGVSxlioRizzuxlQ7xXM=| Registration time: 2023-06-01 17:27| Last authorization session: 2023-06-01 17:27| Access: [Unsuccessful access attempt - 2023-01-01 13:26]
                    Login: +1 123 111 2244| Password: +cJpNBhVw/9nklUJiGl36h6acxPPVN3ceKY8Yqf5HsY=| Salt: YxEDuvdMheUUlhU7vUdA3Omr0S4zUx4Zj85+qlAy9d8=| Registration time: 2023-06-01 17:27| Last authorization session: 2023-06-01 17:27| Access: []
                    ...all subsequent entries.
                    """);
        }

        String testingUser = getTestingUser(userData, login);
        return testingUser.split("\\| ");
    }

    private static String getTestingUser(List<String> userData, String login) {
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
        return testingUser;
    }

    private static String[] getLine(String user) {
        String[] line = user.split("\\| ");
        if (line.length != 6) {
            throw new WrongAnswer("The userData.txt The file must contain user data, each of which consists of 5 sections,\n" + " the sections must be separated by this character - '|' Each new user starts on a new line.");
        }
//          'Login' section testing
        if (!line[0].startsWith("Login:")) {
            throw new WrongAnswer("The string containing user data must start with 'Login:' but your string output equals - " + line[0]);
        }
        return line;
    }

    private boolean verifyPassword(String password, byte[] salt, String hashedPassword) {
        byte[] enteredPasswordHash = hashPassword(password, salt);
        // Decode stored hashed password from Base64 format
        byte[] savedPasswordHash = Base64.getDecoder().decode(hashedPassword);
        return MessageDigest.isEqual(savedPasswordHash, enteredPasswordHash);
    }

    private void majorTestingMethod(String correctOutput, int correctNumberOfLines, int testableOutputTextOnLineNumbered, String output) {
        String looseTestes = "[!.]?$";
        String looseTestes2 = "(don['`]?t)|(doesn['`]?t)";
        String[] regexes = {"^enter[a-z\\s]+?again[a-z\\s]+?complete[a-z\\s]+?registrations?" + looseTestes //0
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
                "^now you can log\\s?in" + looseTestes, //12
                "^registration\\.?$", //13

                "^would you like to login or register[?!.:]?$", //14
                "^1\\.? login, 2\\.? register[?!.:]?$", //15
                "^invalid input, try again ['\"()]?1 or 2['\"()]?[?!.:]?$", //16
                "^goodbye" + looseTestes, //17
                "^invalid choice\\.?,? please enter a valid option number ['\"()]?1['\"()]?\\.?:?$", //18
                "^the entered password does not match the login or the user does not exist" + looseTestes, //19
                "^authorization" + looseTestes, //20
                "^menu" + looseTestes, //21
                "^1[.]? logout" + looseTestes};

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

    private byte[] hashPassword(String password, byte[] salt) {
        char[] passwordChars = password.toCharArray();

        int KEY_LENGTH = 256;
        int ITERATIONS = 10000;
        PBEKeySpec spec = new PBEKeySpec(passwordChars, salt, ITERATIONS, KEY_LENGTH);

        SecretKeyFactory keyFactory;
        try {
            keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return keyFactory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new WrongAnswer("""
                    Error initializing the class - SecretKeyFactory
                    The class is initialized as follows: SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                    Check the method: hashPassword(), строка: 475
                    """);
        }
    }

    private void authorize(String login, String password) {
        String output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);

        output = main.execute(password);
        majorTestingMethod("Authorization successful.", 5, 1, output);
        var splits = output.split("\\n");

        if (splits[2].length() > 60) {
            throw new WrongAnswer("Your creativity '" + splits[2].length() + "' - exceeds the 60 character limit, try shortening the message a bit");
        }
        majorTestingMethod("Menu", 5, 4, output);
        majorTestingMethod("1. Logout", 5, 5, output);
        output = main.execute("1");
        majorTestingMethod("Goodbye", 1, 1, output);

        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
    }

    private void startInit() {
        main = new TestedProgram();
        String output = main.start();

        majorTestingMethod("Would you like to login or register?", 2, 1, output);
        majorTestingMethod("1. Login, 2. Register:", 2, 2, output);
    }

    private final HashMap<String, String> USERS = new HashMap<>();

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


    private int randomize(int i) {
        return new Random().nextInt(i);
    }
}