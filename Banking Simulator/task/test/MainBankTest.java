import org.hyperskill.hstest.dynamic.DynamicTest;
import org.hyperskill.hstest.exception.outcomes.WrongAnswer;
import org.hyperskill.hstest.stage.StageTest;
import org.hyperskill.hstest.testcase.CheckResult;
import org.hyperskill.hstest.testing.TestedProgram;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.hyperskill.hstest.testing.expect.Expectation.expect;

public class MainBankTest extends StageTest<String> {
    private final String CURRENTIME = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"));
    private final String TIMEREGEX = "\\d{1,4}[/\\\\\\s:\\-]\\d{1,2}[/\\\\\\s:\\-]\\d{1,4} \\d{1,2}[\\s:\\-]\\d{1,2}([\\s:\\-]\\d{1,2})?$";
    private final Random random = new Random();
    private final HashSet<String> CURRENCY = new HashSet<>(Set.of("EUR", "GBP", "UAH", "CNY"));
    private final HashMap<String, String> USERS = new HashMap<>();
    @SuppressWarnings("SpellCheckingInspection")
    protected final String APIKEY = "ASDcvv14Dfvv67539a551345n2l34kjklhv012";
    private final File DB = new File("userData.txt");
    private String finLogin;
    private String finPassword;
    private TestedProgram main;
    private String actualCurrency;

    @DynamicTest
    CheckResult test1() /*This test clears the user's file and checks for its existence. It also starts a local server for the user and for tests, which makes it possible to obtain accurate data and limit all tests to local interaction.*/ {
        Runnable runnable = LocalServer::new;
        runnable.run();

        actualCurrency = initLocalServer();
        try {
            Files.writeString(DB.toPath(), "");
        } catch (IOException e) {
            throw new WrongAnswer("Before testing file 'userData.txt' must be empty! Failed to access file.");
        }
        startInit();

        var output = authorize(initNewPerson(generatePhone(true), generatePassword(true)));
        majorTestingMethod("Menu", 2, 1, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 2, 2, output);
        output = main.execute("4");
        majorTestingMethod("Goodbye", 1, 1, output);

        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        return CheckResult.correct();
    }

    @DynamicTest(repeat = 10)
    CheckResult test2() /*This test initializes registration a new persons for next tests*/ {
        var login = generatePhone(true);
        var password = generatePassword(true);

        startInit();

        var output = authorize(initNewPerson(login, password));
        output = main.execute("1");
        majorTestingMethod("Exchange rates", 2, 1, output);
        majorTestingMethod("1. EUR, 2. GBP, 3. UAH, 4. CNY, 5. Back", 2, 2, output);
        for (int i = 0; i < randomize(10); i++) {
            output = main.execute(forAnyCase[randomize(forAnyCase.length - 1)].toString().replaceAll("\\d", ""));
            majorTestingMethod("Incorrect currency code, try again.", 2, 1, output);
            majorTestingMethod("(1. EUR, 2. GBP, 3. UAH, 4. CNY, or 5. Back):", 2, 2, output);
        }
        output = main.execute("5");
        majorTestingMethod("Menu", 2, 1, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 2, 2, output);
        output = main.execute("4");
        majorTestingMethod("Goodbye", 1, 1, output);

        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        return CheckResult.correct();
    }

    @DynamicTest(repeat = 10)
    CheckResult test3() /*Some currency changes tests*/ {
        var login = USERS.keySet().stream().toList().get(randomize(USERS.size()));
        var password = USERS.get(login);
        startInit();

        var output = main.execute("1");
        majorTestingMethod("Authorization", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);


        output = authorize(main.execute(password));

        majorTestingMethod("Menu", 2, 1, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 2, 2, output);

        output = main.execute("1");

        majorTestingMethod("Exchange rates", 2, 1, output);
        majorTestingMethod("1. EUR, 2. GBP, 3. UAH, 4. CNY, 5. Back", 2, 2, output);

        for (int i = 1; i < randomize(5); i++) {
            output = main.execute(String.valueOf(i));
            List<String> resOutput = List.of(output.split("\n"));

            String compare = null;
            for (var set : CURRENCY.stream().toList()) {
                if (resOutput.get(0).contains(set)) {
                    compare = parseExchangeRate(actualCurrency, set);
                    break;
                }
            }

            if (compare != null && !compare.toLowerCase().trim().equals(resOutput.get(0).toLowerCase().trim())) {
                throw new WrongAnswer("Your output of this currency does not match the HTTP request from our local server, Your HTTP response: '" + output.split("\n")[0] + "'\n" + "Correct HTTP response: " + compare + "\nAlso, do not forget about the correct apikey, case is important! apiKey -" + APIKEY);
            }
            majorTestingMethod("Would you like to choose another currency? (Y/N)", 3, 3, output);

            output = main.execute("n");
            majorTestingMethod("Menu", 2, 1, output);
            majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 2, 2, output);

            output = main.execute("1");
            majorTestingMethod("Exchange rates", 2, 1, output);
            majorTestingMethod("1. EUR, 2. GBP, 3. UAH, 4. CNY, 5. Back", 2, 2, output);

        }

        output = main.execute("5");
        majorTestingMethod("Menu", 2, 1, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 2, 2, output);

        output = main.execute(forAnyCase[randomize(forAnyCase.length - 1)].toString().replaceAll("[1-4]", ""));
        majorTestingMethod("Invalid choice", 2, 1, output);
        majorTestingMethod("Select a menu item: [num] 1, 2, 3, 4: ", 2, 2, output);

        output = main.execute("4");
        majorTestingMethod("Goodbye", 1, 1, output);
        return CheckResult.correct();
    }

    //    2. Chat Support testing section
    private void initChatForTesting() /*this test initializes and tests all output strings until the autoTestingChat method is initialized.*/ {
        var login = USERS.keySet().stream().toList().get(randomize(USERS.size()));
        var password = USERS.get(login);
        startInit();

        var output = main.execute("1");
        majorTestingMethod("Authorization", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);


        output = authorize(main.execute(password));

        majorTestingMethod("Menu", 2, 1, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 2, 2, output);

        output = main.execute("2");
        majorTestingMethod("Chat", 2, 1, output);
        majorTestingMethod("1. Send Message, 2. Back", 2, 2, output);
        for (int i = 0; i < randomize(10); i++) {
            output = main.execute(forAnyCase[randomize(forAnyCase.length - 1)].toString().replaceAll("[1-2]", ""));
            majorTestingMethod("Invalid choice.", 2, 1, output);
            majorTestingMethod("1. Send Message, 2. Back: ", 2, 2, output);
        }

        autoTestingChat(main.execute("1")); //testing first fourth lines
//        [Simulation] 'Question' 'dd-MM-yyyy HH:mm:ss'
//        System message: Operator Sam is connected 'dd-MM-yyyy HH:mm:ss'
//        'Operator name': 'Operator answer' 'dd-MM-yyyy HH:mm:ss'
//        System message: Did you get an answer to your question? (Y/N) 'dd-MM-yyyy HH:mm:ss'
    }

    @DynamicTest(repeat = 10)
    CheckResult test4() /*Another test to check the output of messages in the section 2. Chat Support*/ {
        initChatForTesting();

        String output = main.execute("n");
        var outputArray = output.split("\n");

        var sys = "system message:";
        if (!outputArray[0].toLowerCase().startsWith(sys)) {
            throw new WrongAnswer("Your program in this part of the chat should start with text '" + sys + "'\n" + "but your program printed '" + outputArray[0] + "'");
        }

        autoTestingChatAfterSimulation(output);
        var tmpList = outputArray[outputArray.length - 1];
        var tmpBoolean = tmpList.contains("another");

        if (tmpList.contains("(Y/N)") && !tmpBoolean) {
            output = main.execute("y");
        } else if (tmpBoolean) {
            output = main.execute("n");
        }

        majorTestingMethod("Menu", 4, 3, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 4, 4, output);
        output = main.execute("4");
        majorTestingMethod("Goodbye", 1, 1, output);

        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        return CheckResult.correct();
    }

    @DynamicTest(repeat = 10)
    CheckResult test5()/*Simple Chat Check*/ {
        initChatForTesting();
        String output;
        for (int i = 0; i < randomize(10); i++) {
            output = main.execute(forAnyCase[randomize(forAnyCase.length - 1)].toString().replaceAll("[yYnN]", ""));
            majorTestingMethod("Invalid input! (Y/N)", 1, 1, output);
        }

        output = main.execute("y");
        autoTestingChatAfterSimulation(output);

        majorTestingMethod("Menu", 4, 3, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 4, 4, output);

        output = main.execute("4");
        majorTestingMethod("Goodbye", 1, 1, output);
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        return CheckResult.correct();
    }

    @DynamicTest(repeat = 3)
    CheckResult test6() /*This test checks the chat question count and testing chat msg output*/ {
        initChatForTesting();
        int chatQuestionCount = 1;


        String[] tmpReg = {"We'?re sorry,? but there are currently no available operators,? please contact us later\\.?\\s?-?", "Ask another question\\?\\s?['\"(]y[,.\\s/]?n['\")]\\s?", "Chat completed\\.?,? Redirecting to the main menu\\.?\\s?"};
        String output = main.execute("n");
        var outputArray = output.split("\n");


        while (!outputArray[0].toLowerCase().matches("^system message: simulation completed\\s?" + TIMEREGEX)) {
            autoTestingChatAfterSimulation(output);


            for (int i = 0; i < tmpReg.length; i++) {
                var regex = "^System message: " + tmpReg[i] + TIMEREGEX;
                regex = regex.toLowerCase();
                var finRegex = Pattern.matches(regex, outputArray[0].toLowerCase());
                switch (i) {
                    case 0, 2 -> {
                        if (finRegex) {
                            majorTestingMethod("Menu", 4, 3, output);
                            majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 4, 4, output);

                            output = main.execute("2");
                            majorTestingMethod("Chat", 2, 1, output);
                            majorTestingMethod("1. Send Message, 2. Back", 2, 2, output);

                            output = main.execute("1");
                            autoTestingChat(output);
                            chatQuestionCount++;

                            output = main.execute("n");
                        }
                    }
                    case 1 -> {
                        if (finRegex) {
                            autoTestingChatAfterSimulation(output);

                            output = main.execute("y");
                            autoTestingChat(output);
                            chatQuestionCount++;

                            output = main.execute("N");
                        }
                    }
                }
                outputArray = output.split("\n");
            }
            if (chatQuestionCount > 15) {
                throw new WrongAnswer("Your program must meet the requirements and contain 15 questions, at the moment there is an initialization of the question number - " + chatQuestionCount);
            }
            if (output.split("\n")[0].toLowerCase().matches("^system message: simulation completed\\s?" + TIMEREGEX) && chatQuestionCount < 15) {
                throw new WrongAnswer("Wrong number of questions. Based on the requirements, there should be 15 of them.\n" + "Simulation ended at question number - " + chatQuestionCount);
            }
        }
        output = main.execute("4");
        majorTestingMethod("Goodbye", 1, 1, output);
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        return CheckResult.correct();
    }

//    Ended testing section 2. Chat support

//    3. Security Settings testing section {

    private void testingCaseForSecuritySettingsSectionAccess(String correctLogin, String badPassword, String correctPassword)/*
    Initializing a test to perform basic partition checks '2. Access Settings' */ {
        startInit();
        String output = main.execute("1");
        majorTestingMethod("Authorization", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        output = main.execute(correctLogin);
        majorTestingMethod("Password:", 1, 1, output);
        output = main.execute(badPassword);
        if (!badPassword.equals(correctPassword)) {
            majorTestingMethod("The entered password does not match the login or the user does not exist.", 3, 1, output);

            majorTestingMethod("Login:", 3, 3, output);
            output = main.execute(correctLogin);
            majorTestingMethod("Password:", 1, 1, output);
            output = main.execute(correctPassword);
        }
        output = authorize(output);
        majorTestingMethod("Menu", 2, 1, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 2, 2, output);
        output = main.execute("3");
        majorTestingMethod("Security Settings", 2, 1, output);
        majorTestingMethod("1. Change Password, 2. Access Settings, 3. Back:", 2, 2, output);
    }

    @DynamicTest
    CheckResult test7() /*Initializing a user for volume testing and checking the change password method. */ {
        startInit();
        finLogin = generatePhone(true);
        finPassword = generatePassword(true);
        String output;
        for (int i = 0; i < randomize(13); i++) {
            output = main.execute("");
            majorTestingMethod("Invalid input, try again '1 or 2':", 1, 1, output);
            output = main.execute(forAnyCase[randomize(forAnyCase.length - 1)].toString().replaceAll("\\d", ""));
            majorTestingMethod("Invalid input, try again '1 or 2':", 1, 1, output);
        }


        output = authorize(initNewPerson(finLogin, finPassword));
        majorTestingMethod("Menu", 2, 1, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 2, 2, output);
        for (int j = 0; j < randomize(15) + 3; j++) {
            output = main.execute("3");
            majorTestingMethod("Security Settings", 2, 1, output);
            majorTestingMethod("1. Change Password, 2. Access Settings, 3. Back:", 2, 2, output);

            for (int i = 0; i < randomize(3); i++) {
                output = main.execute(forAnyCase[randomize(forAnyCase.length - 1)].toString().replaceAll("[1-3]", ""));
                majorTestingMethod("Invalid option. Please try again.", 2, 1, output);
                majorTestingMethod("Select a menu item: [num] 1, 2, 3: ", 2, 2, output);
            }

            output = main.execute("1");
            majorTestingMethod("Enter your current password: ", 1, 1, output);

            output = main.execute(generatePassword(false));
            majorTestingMethod("Enter your new password:", 1, 1, output);
            output = main.execute(generatePassword(true));
            majorTestingMethod("Failed to change password. Please check your current password and try again.", 4, 1, output);
            majorTestingMethod("Menu", 4, 3, output);
            majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 4, 4, output);
        }

        output = main.execute("3");
        majorTestingMethod("Security Settings", 2, 1, output);
        majorTestingMethod("1. Change Password, 2. Access Settings, 3. Back:", 2, 2, output);

        output = main.execute("1");
        majorTestingMethod("Enter your current password: ", 1, 1, output);
        output = main.execute(finPassword);
        majorTestingMethod("Enter your new password:", 1, 1, output);
        for (int i = 0; i < randomize(15) + 3; i++) {
            output = main.execute(generatePassword(false));
            majorTestingMethod("Incorrect password format", 2, 1, output);
            majorTestingMethod("Enter your new password: ", 2, 2, output);
        }
        finPassword = generatePassword(true);
        output = main.execute(finPassword);
        majorTestingMethod("Password successfully changed.", 4, 1, output);

        majorTestingMethod("Menu", 4, 3, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 4, 4, output);

        output = main.execute("4");
        majorTestingMethod("Goodbye", 1, 1, output);
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        return CheckResult.correct();
    }

    @DynamicTest
    CheckResult test8()/*Testing for missing string 'Unsuccessful access attempt - yyyy-MM-dd HH:mm'
     And checking the output for this case - No suspicious activity detected.*/ {
        testingCaseForSecuritySettingsSectionAccess(finLogin, finPassword, finPassword);
        String output = main.execute("2");
        var outputArray = output.split("\n");

        majorTestingMethod(outputArray[0].trim(), 5, 1, output);
        majorTestingMethod("No suspicious activity detected.", 5, 2, output);

        majorTestingMethod("Menu", 5, 4, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 5, 5, output);

        output = main.execute("4");
        majorTestingMethod("Goodbye", 1, 1, output);
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        return CheckResult.correct();
    }

    @DynamicTest
    CheckResult test9()/*Testing the write method 'Unsuccessful access attempt - yyyy-MM-dd HH:mm' 1 - attempt*/ {
        testingCaseForSecuritySettingsSectionAccess(finLogin, generatePassword(false), finPassword);
        String output = main.execute("2");
        var outputArray = output.split("\n");
        majorTestingMethod(outputArray[0].trim(), 5, 1, output);
        majorTestingMethod(outputArray[1].trim(), 5, 2, output);
        majorTestingMethod("Menu", 5, 4, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 5, 5, output);

        output = main.execute("4");
        majorTestingMethod("Goodbye", 1, 1, output);
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        return CheckResult.correct();
    }

    @DynamicTest
    CheckResult test10() /*Testing the write method 'Unsuccessful access attempt - yyyy-MM-dd HH:mm' 2 - attempt*/ {
        testingCaseForSecuritySettingsSectionAccess(finLogin, generatePassword(true), finPassword);
        String output = main.execute("2");
        var outputArray = output.split("\n");
        majorTestingMethod(outputArray[0].trim(), 6, 1, output);
        majorTestingMethod(outputArray[1].trim(), 6, 2, output);
        majorTestingMethod(outputArray[2].trim(), 6, 3, output);
        majorTestingMethod("Menu", 6, 5, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 6, 6, output);
        output = main.execute("4");
        majorTestingMethod("Goodbye", 1, 1, output);
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        return CheckResult.correct();
    }

    @DynamicTest
    CheckResult test11()/*Testing the write method 'Unsuccessful access attempt - yyyy-MM-dd HH:mm' 3 - attempt*/ {
        testingCaseForSecuritySettingsSectionAccess(finLogin, generatePassword(true), finPassword);
        String output = main.execute("2");
        var outputArray = output.split("\n");
        majorTestingMethod(outputArray[0].trim(), 7, 1, output);
        majorTestingMethod(outputArray[1].trim(), 7, 2, output);
        majorTestingMethod(outputArray[2].trim(), 7, 3, output);
        majorTestingMethod(outputArray[3].trim(), 7, 4, output);

        majorTestingMethod("Menu", 7, 6, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 7, 7, output);

        output = main.execute("4");
        majorTestingMethod("Goodbye", 1, 1, output);
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        return CheckResult.correct();
    }

    @DynamicTest
    CheckResult test12() /*Final testing the write method 'Unsuccessful access attempt - yyyy-MM-dd HH:mm'
    to the correct number of lines when reading and outputting in a section 2. Access Settings
    And delete tested user from the database*/ {
        testingCaseForSecuritySettingsSectionAccess(finLogin, "", finPassword);
        String output = main.execute("2");
        var outputArray = output.split("\n");
        majorTestingMethod(outputArray[0].trim(), 7, 1, output);
        majorTestingMethod(outputArray[1].trim(), 7, 2, output);
        majorTestingMethod(outputArray[2].trim(), 7, 3, output);
        majorTestingMethod(outputArray[3].trim(), 7, 4, output);

        majorTestingMethod("Menu", 7, 6, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 7, 7, output);

        output = main.execute("3");
        majorTestingMethod("Security Settings", 2, 1, output);
        majorTestingMethod("1. Change Password, 2. Access Settings, 3. Back:", 2, 2, output);

        output = main.execute("1");
        majorTestingMethod("Enter your current password: ", 1, 1, output);

        output = main.execute(finPassword);
        majorTestingMethod("Enter your new password:", 1, 1, output);

        output = main.execute(finPassword);
        majorTestingMethod("Current and new passwords are the same! Password cannot be changed", 4, 1, output);

        majorTestingMethod("Menu", 4, 3, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 4, 4, output);

        output = main.execute("4");
        majorTestingMethod("Goodbye", 1, 1, output);
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        List<String> resList = new ArrayList<>();
        try {
            var logDel = finLogin.replaceAll("\\D", "");
            var cleaner = Files.readAllLines(Path.of(DB.getPath()));
            cleaner.forEach(line -> {
                if (!line.split("\\| ")[0].replaceAll("\\D", "").equals(logDel)) {
                    resList.add(line);
                }
            });
            Files.write(Path.of(DB.getPath()), resList, StandardCharsets.UTF_8);
            USERS.remove(finLogin);
        } catch (Exception e) {
            throw new WrongAnswer("Error while reading\\writing from file 'userData.txt'");
        }
        return CheckResult.correct();
    }

    // } Ends testing section of Security Settings


    // File 'userData.txt' testing section {
    HashMap<String, String> accessUsersMap = new HashMap<>();

    @DynamicTest(repeat = 30)
    CheckResult test16()/*Database file testing, filling with new users*/ {
        startInit();
        var output = authorize(initNewPerson(generatePhone(true), generatePassword(true)));

        majorTestingMethod("Menu", 2, 1, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 2, 2, output);
        output = main.execute("4");
        majorTestingMethod("Goodbye", 1, 1, output);

        return CheckResult.correct();
    }

    @DynamicTest(repeat = 20)
    CheckResult test17() /* Random format test triggers incorrect password entry of selected users*/ {
        startInit();

        String login = USERS.keySet().stream().toList().get(randomize(USERS.size()));
        while (accessUsersMap.containsKey(login)) {
            login = USERS.keySet().stream().toList().get(randomize(USERS.size()));
        }

        String password;
        String output = main.execute("1");
        majorTestingMethod("Authorization", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
        int countAttempts = 0;


        for (int i = 0; i < randomize(3); i++) {
            output = main.execute(login);
            majorTestingMethod("Password:", 1, 1, output);
            output = main.execute(generatePassword(false));
            majorTestingMethod("The entered password does not match the login or the user does not exist.", 3, 1, output);

            majorTestingMethod("Login:", 3, 3, output);
            countAttempts++;
        }
        accessUsersMap.put(login, countAttempts + " - " + CURRENTIME);
        password = USERS.get(login);

        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);

        output = authorize(main.execute(password));

        majorTestingMethod("Menu", 2, 1, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 2, 2, output);

        output = main.execute("4");
        majorTestingMethod("Goodbye", 1, 1, output);
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        return CheckResult.correct();
    }

    @SuppressWarnings("SpellCheckingInspection")
    private void fileTesting(String login, String password, String accessTime, int getAccessAttemptsCountRecordedTest) /* Major method for testing files,very sensitive to changes, contains a large amount of checked information from the user's file, for testing.*/ {

        List<String> userData;
        try {
            userData = Files.readAllLines(Path.of(DB.getPath()));
        } catch (IOException e) {
            throw new WrongAnswer("Unable to read userData.txt file or file was not found: " + e.getMessage());
        }

        if (userData.size() != USERS.size()) {
            throw new WrongAnswer("""
                    The userData.txt file should contain data about users who were registered during the tests.
                    User data must start on a new line.
                    Example:
                    Login: +(1) 123 123 3333| Password: H7zhSEcK3ATrndB7gvJmd5Zbqtiwk9lrhcyeHhUEk5Y=| Salt: pTXvgvjebxPh2qLRqIdvoZuX8TxyR3u+ZEoRhFubgG8=| Registration Time: 2023-06-01 17:26| Last Authorization Session: 2023-06-01 17:26| Access: [Unsuccessful access attempt - 2023-08-01 11:26, Unsuccessful access attempt - 2023-08-01 12:26, Unsuccessful access attempt - 2023-08-01 13:26]
                    Login: 1 342 343 5544| Password: Of9ciui/5d/Tlv94m+cVCx5wdWG1QbRqMldPRNSvnvc=| Salt: DRySPA7xv3oTxBzFDUTgzkuDGVSxlioRizzuxlQ7xXM=| Registration Time: 2023-06-01 17:27| Last Authorization Session: 2023-06-01 17:27| Access: [Unsuccessful access attempt - 2023-01-01 13:26]
                    Login: +1 123 111 2244| Password: +cJpNBhVw/9nklUJiGl36h6acxPPVN3ceKY8Yqf5HsY=| Salt: YxEDuvdMheUUlhU7vUdA3Omr0S4zUx4Zj85+qlAy9d8=| Registration Time: 2023-06-01 17:27| Last Authorization Session: 2023-06-01 17:27| Access: []
                    ...all subsequent entries.
                    """);
        }
        String testingUser = getTestingUser(login, userData);
        var testingUserSections = testingUser.split("\\| ");
        String savedHashedPassword = testingUserSections[1].substring(10);
        byte[] savedSalt = Base64.getDecoder().decode(testingUserSections[2].substring(6));
        if (!verifyPassword(password, savedSalt, savedHashedPassword)) {
            throw new WrongAnswer("""
                    The password and salt was not saved in the database, or it was not saved correctly.
                    Example correct password and salt:
                    Password: MuIpL4JJbjRpTGdg2oMawHWMEt91AiLxGFgoiw8yjC8=| Salt: Ypt72qwV6/5QXKcmG84WJ/dfnydrlxy1v+ajBBfKE/0=|
                    Where '|' is a delimiter.""");
        }
//          'Registration Time' section testing
        String registrationTimeSection = testingUserSections[3].substring(19);
        if (!registrationTimeSection.matches(TIMEREGEX)) {
            throw new WrongAnswer("The Registration Time section was not saved in the database, or it was not saved correctly.");
        }

//          'Last Authorization Session' section testing
        if (!testingUserSections[4].substring(28).matches(TIMEREGEX)) {
            throw new WrongAnswer("The 'Last Authorization Session' section was not saved in the database, or it was not saved correctly.");
        }

//          'Access' section testing
        var a = Integer.parseInt(registrationTimeSection.substring(registrationTimeSection.length() - 2)); // getDBTime
        var b = Integer.parseInt(accessTime.substring(accessTime.length() - 2)); // getTestTime
        int scale;
        if (a > b) {
            scale = a - b;
        } else {
            scale = b - a;
        }
        switch (scale)/* The probability of this event out of 1000 is on average close
                                 to 60 cases when the time difference is allowed in 1 maximum 2 minutes.
            Private  int timeTest()/*result: Detected extremely rare unlikely event: 45
        4935 {
                                    int matchProbability = 0;
                                    int rare = 0;
                                    int a;
                                    int b;
                                    for (int i = 0; i < 100000; i++) {
                                        int scale;

                                        a = new Random().nextInt(60);
                                        b = new Random().nextInt(60);
                                        if (a > b) {
                                            scale = a - b;
                                        } else {
                                            scale = b - a;
                                        }
                                        if (scale == 0 || scale == 1) {
                                            matchProbability++;
                                        } else {
                                            if (scale == 59) {
                                                rare++;
                                            }
                                        }
                                    }
                                    System.out.println("Detected extremely rare unlikely event: " + rare);
                                    return matchProbability;
                                }
                                */ {
            case 0, 1, 2, 59:

                break;
            default:
                throw new WrongAnswer("The time to save an unsuccessful authorization attempt is not correct or the method of saving the authorization time is implemented incorrectly." + "\n" + "A line from the 'userData.txt' file containing the time to store the failed authorization: " + registrationTimeSection + "\n" + "The time recorded by the tests: " + accessTime);
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

        if (getDataBaseAccessAttemptsCountRecorded != getAccessAttemptsCountRecordedTest) {
            throw new WrongAnswer("""
                                          Data 'Access' section was not saved in the database, or it was not saved correctly.
                                          Example correct user data save:
                                          Login: +(1)-944-201-1476| Password: Z/TEmztuN3P1BxeAD/SzP5N7zTXDK0x0dJe5dckgBks=| Salt: ccWkx8kddf935lXn9GtZ4CktR12XfdDJUX0WQkSGZ2M=| Registration Time: 2023-08-27 18:15| Last Authorization Session: 2023-08-27 18:15| Access: [Unsuccessful access attempt - 2023-08-27 18:15]
                                          Your string contains -\s
                                          """ + testingUser);
        }
        if (getDataBaseAccessAttemptsCountRecorded > 3) {
            throw new WrongAnswer("The 'Access:' section should have contained one entry 'Unsuccessful access attempt - yyyy-MM-dd HH:mm' - no more than 3 entries.");
        }
    }

    private static String getTestingUser(String login, List<String> userData) {
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
            throw new WrongAnswer("The userData.txt The file must contain user data, each of which consists of 6 sections,\n" + " the sections must be separated by this character - '|' Each new user starts on a new line.");
        }
//          'Login' section testing
        if (!line[0].startsWith("Login:")) {
            throw new WrongAnswer("The string containing user data must start with 'Login:' but your string output equals - " + line[0]);
        }
        return line;
    }

    @DynamicTest(repeat = 10)
    CheckResult test18() /* after all the tests, initializes checking the database */ {
        startInit();
        String output = main.execute("1");
        majorTestingMethod("Authorization", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

//      If you have any questions, I think this will answer - 'accessUsersMap.put(login, countAttempts + " - " + CURRENTIME);'
//
        var timeLength = CURRENTIME.length() + 3;
        var getLoginKey = accessUsersMap.keySet().stream().toList().get(randomize(accessUsersMap.size()));

        output = main.execute(getLoginKey);
        majorTestingMethod("Password:", 1, 1, output);
        output = authorize(main.execute(USERS.get(getLoginKey)));

        majorTestingMethod("Menu", 2, 1, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 2, 2, output);

        var getAttemptValue = accessUsersMap.get(getLoginKey);
        fileTesting(getLoginKey, USERS.get(getLoginKey), getAttemptValue.substring(4), Integer.parseInt(getAttemptValue.substring(0, getAttemptValue.length() - timeLength)));
        output = main.execute("4");
        majorTestingMethod("Goodbye", 1, 1, output);
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program should finish");
        }
        return CheckResult.correct();
    }

    @DynamicTest(repeat = 3)
    CheckResult test19() /* Various tests for all stages of the project */ {
        startInit();
        String output = main.execute("2");
        majorTestingMethod("Registration", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
        String login;
        String password;
        for (int i = 0; i < randomize(30); i++) {
            login = USERS.keySet().stream().toList().get(randomize(USERS.size()));

            output = main.execute(login);
            majorTestingMethod("Login is already taken, try another login.", 2, 1, output);
            majorTestingMethod("Login:", 2, 2, output);
        }
        login = generatePhone(true);
        password = generatePassword(true);

        for (int i = 0; i < randomize(30); i++) {
            output = main.execute(generatePhone(false));
            majorTestingMethod("Wrong login format, try again", 2, 1, output);
            majorTestingMethod("Login:", 2, 2, output);
        }

        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
        for (int i = 0; i < randomize(30); i++) {

            output = main.execute(generatePassword(false));
            majorTestingMethod("Wrong password format, try again", 2, 1, output);
            majorTestingMethod("Password:", 2, 2, output);
        }
        output = main.execute(password);
        majorTestingMethod("Enter the data again to complete the registration", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);

        output = main.execute(password);
        majorTestingMethod("Congratulations on your successful registration!", 5, 1, output);
        majorTestingMethod("Now you can log in!", 5, 2, output);

        majorTestingMethod("Authorization", 5, 4, output);
        majorTestingMethod("Login:", 5, 5, output);
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
        return CheckResult.correct();
    }

    @DynamicTest(repeat = 10)
    CheckResult test20()
        /**/ {
        var login = generatePhone(true);
        var password = generatePassword(true);
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
        output = main.execute(generatePhone(true));
        majorTestingMethod("Password:", 1, 1, output);
        //Login and password don't match.

        output = main.execute(generatePassword(true));
        majorTestingMethod("Login and password don't match.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
        output = main.execute(generatePhone(true));
        majorTestingMethod("Password:", 1, 1, output);
        output = main.execute(password);
        majorTestingMethod("Login doesn't match.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
        output = main.execute(generatePassword(true));
        majorTestingMethod("Password doesn't match.", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
        output = main.execute(password);
        majorTestingMethod("Congratulations on your successful registration!", 5, 1, output);
        majorTestingMethod("Now you can log in!", 5, 2, output);
        majorTestingMethod("Authorization", 5, 4, output);
        majorTestingMethod("Login:", 5, 5, output);
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);
        output = authorize(main.execute(password));
        majorTestingMethod("Menu", 2, 1, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 2, 2, output);
        output = main.execute("4");
        majorTestingMethod("Goodbye", 1, 1, output);
        return CheckResult.correct();
    }

    /*\/\/\/The following are all the methods used in testing project stages.\/\/\/*/

    //***MAJOR TESTING METHOD FOR ALL THE TESTS***

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

        if (check.toLowerCase().startsWith("you have been registered:")) {
            throw new WrongAnswer("""
                                          The user database does not correctly store information in the section 'Registration Time'.
                                          Correct database storage option - 'Registration Time: yyyy-MM-dd HH:mm'
                                          Output receive -\s""" + outputLines.get(0));
        }
        if (check.toLowerCase().startsWith("unsuccessful access attempt")) {
            throw new WrongAnswer("""
                                          The user database does not correctly store information in the section 'Access: ' or your implementation method for displaying the output is incorrect.
                                          How the output should look like:
                                          > You have been registered: yyyy-MM-dd HH:mm
                                          > Unsuccessful access attempt - yyyy-MM-dd HH:mm
                                          > Unsuccessful access attempt - yyyy-MM-dd HH:mm
                                          > Unsuccessful access attempt - yyyy-MM-dd HH:mm
                                          Where ('> ') is the output of your program.
                                          Correct database storage - 'Access: Unsuccessful access attempt - yyyy-MM-dd HH:mm'
                                          Also, do not forget about the number of 'Unsuccessful access attempt' entries in this section, there should be no more than 3 of them.
                                          Output receive :\s""" + outputLines.get(1));
        }
        throw new WrongAnswer("Your program should print '" + correctOutput + "' but it printed '" + check + "'");
    } /* Contains a set of test methods and checks for testing the all stages and is the major testing method. !! Is very sensitive to any changes !! */

    private String[] getRegexes() {
        String looseTestes = "[!.]?$";
        String looseTestes2 = "(don['`]?t)|(doesn['`]?t)";
        String orRegex = "['\"()]?";
        String yOrN = "\\s?['\"(]y[,.\\s/]?n['\")][!.:]?$";
        String looseChoice = "^invalid choice\\.?,?";
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
                "^now you can log\\s?in" + looseTestes, //12
                "^registration\\.?$", //13

                "^would you like to login or register[?!.:]?$", //14
                "^1\\.? login, 2\\.? register[?.:]?$", //15
                "^invalid input, try again ['\"()]?1 or 2['\"()]?[?!.:]?$", //16
                "^goodbye" + looseTestes, //17
                looseChoice + " please enter a valid option number " + orRegex + "1" + orRegex + " or " + orRegex + "2" + orRegex + "\\.?:?$", //18
                "^the entered password does not match the login or the user does not exist" + looseTestes, //19
                "^authorization" + looseTestes, //20

                "^menu" + looseTestes, //21
                "^1\\.? Exchange Rates, 2\\.? Chat Support, 3\\.? Security Settings, 4\\.? Exit\\.?$",  //22
                "^exchange rates[:.]?$", "^1[.]? EUR, 2[.]? GBP, 3[.]? UAH, 4[.]? CNY, 5[.]? Back[?.:]?$", "^\\(1\\. EUR, 2\\. GBP, 3\\. UAH, 4\\. CNY\\.?,? or 5\\. Back\\):?\\.?!?$", //23
                "^incorrect currency code,? try again" + looseTestes, //24
                "^would you like to choose another currency\\?" + yOrN, //25
                "^invalid input[!.,]" + yOrN, //26
                looseChoice + "$", //27

                "^1[.,] Send Message[.,]? 2[.,] Back[:\\-]?\\s?$", looseChoice + "(((again)|(try))+?[.!]?)?$", "^No suspicious activity detected\\.?$", "^you have been registered[:\\-]\\s?" + TIMEREGEX, "^Failed to change password\\.?,? Please check your current password and try again\\.?$", "^unsuccessful access attempt\\s-\\s" + TIMEREGEX, "^Enter your current password:\\s?$", "^Enter your new password:\\s?$", "^Current and new passwords are the same[!.,] Password cannot be changed" + looseTestes, "^Incorrect password format$", "^Password successfully changed[.!]?$", "^Select a? menu item[:.,\\-] [\\[(]num[])] [1-4,.\\s]+?[:.\\s]+?$", "^Chat$", "^Security Settings$", "1[,.\\s]+?Change Password, 2[,.\\s]+?Access Settings, 3[,.\\s]+?Back[:.!]?\\s?$", "^Invalid option[.,]? Please try again[.!]?$"};
    }
    //***MAJOR TESTING METHOD FOR ALL THE TESTS***

    private void startInit() /* Contains the initial check strings output at application startup and initiates TestedProgram main */ {
        main = new TestedProgram();
        var getInput = main.start().trim().split("\\n");

        if (getInput.length != 2) {
            throw new WrongAnswer("Your program should print " + 2 + " lines but it printed " + getInput.length + " line(s).");
        }
        if (!Pattern.matches("^would you like to login or register[?!.:]?$", getInput[0].toLowerCase())) {
            throw new WrongAnswer("Your program should print " + "Would you like to login or register?" + " lines but it printed '" + getInput[0] + "' string.");
        }
        if (!Pattern.matches("^1\\.? login, 2\\.? register[?.:]?\\s?$", getInput[1].toLowerCase())) {
            throw new WrongAnswer("Your program should print " + "1. Login, 2. Register:" + " lines but it printed " + getInput[1] + " string.");
        }
    }

    private String authorize(String output) /* Contains authorization output strings and initiates an entry check and return of all menu items */ {

        var splits = output.split("\n");
        majorTestingMethod("Authorization successful.", 5, 1, output);
        if (splits[2].length() > 60) {
            throw new WrongAnswer("Your creativity '" + splits[2].length() + "' - exceeds the 60 character limit, try shortening the message a bit");
        }
        majorTestingMethod("Menu", 5, 4, output);
        majorTestingMethod("1. Exchange Rates, 2. Chat Support, 3. Security Settings, 4. Exit", 5, 5, output);
        for (int i = 0; i < 3; i++) {
            if (i == 0) {
                output = main.execute("1");
                majorTestingMethod("Exchange rates", 2, 1, output);
                majorTestingMethod("1. EUR, 2. GBP, 3. UAH, 4. CNY, 5. Back", 2, 2, output);
                for (int forceFailedCurrency = 0; forceFailedCurrency < randomize(3) + 1; forceFailedCurrency++) {
                    output = main.execute(forAnyCase[randomize(forAnyCase.length - 1)].toString().replaceAll("\\d", ""));
                    majorTestingMethod("Incorrect currency code, try again.", 2, 1, output);
                    majorTestingMethod("(1. EUR, 2. GBP, 3. UAH, 4. CNY, or 5. Back):", 2, 2, output);
                }
                output = main.execute("5");
            }
            if (i == 1) {
                output = main.execute("2");
                majorTestingMethod("Chat", 2, 1, output);
                majorTestingMethod("1. Send Message, 2. Back", 2, 2, output);
                for (int forceFailedChat = 0; forceFailedChat < randomize(3) + 1; forceFailedChat++) {
                    output = main.execute(forAnyCase[randomize(forAnyCase.length - 1)].toString().replaceAll("[1-2]", ""));
                    majorTestingMethod("Invalid choice.", 2, 1, output);
                    majorTestingMethod("1. Send Message, 2. Back: ", 2, 2, output);
                }
                output = main.execute("2");
            }
            if (i == 2) {
                output = main.execute("3");
                majorTestingMethod("Security Settings", 2, 1, output);
                majorTestingMethod("1. Change Password, 2. Access Settings, 3. Back: ", 2, 2, output);
                for (int forceFailedSecurity = 0; forceFailedSecurity < randomize(3) + 1; forceFailedSecurity++) {
                    output = main.execute(forAnyCase[randomize(forAnyCase.length - 1)].toString().replaceAll("[1-3]", ""));
                    majorTestingMethod("Invalid option. Please try again.", 2, 1, output);
                    majorTestingMethod("Select a menu item: [num] 1, 2, 3: ", 2, 2, output);
                }
                output = main.execute("3");
            }
        }
        return output;
    }

    private String initNewPerson(String login, String password) /* Contains a set of test methods and checks for creating a new user */ {

        String output = main.execute("2");
        majorTestingMethod("Registration", 2, 1, output);
        majorTestingMethod("Login:", 2, 2, output);

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
        majorTestingMethod("Login:", 5, 5, output);
        output = main.execute(login);
        majorTestingMethod("Password:", 1, 1, output);

        output = main.execute(password);
        USERS.put(login, password);
        return output;
    }

    private void autoTestingChat(String outText) /* Contains various test options for section 2. Chat Support And is the major test for section 2. Chat Support*/ {
        String yOrNRegex = "\\s?['\"(]y[,.\\s/]?n['\")]\\s?";
        String sysMsgRegex = "^System message: ";

        String[] questionsRegexes = {"(activate)[a-z\\s]+?(card)\\?\\s?", "(check)[a-z\\s]+?(balance)[a-z\\s]+?(card)\\?\\s?", "(should)[a-z\\s]+?(card)[a-z\\s]+?(been)[a-z\\s]+?(stolen)\\?\\s?", "(can)[a-z\\s]+?(block)[a-z\\s]+?(card)\\?\\s?", "(should)[a-z\\s]+?(lose)[a-z\\s]+?(card)\\?\\s?", "(order)[a-z\\s]+?(new)[a-z\\s]+?(card)\\?\\s?", "(can)[a-z\\s]+?(update)[a-z\\s]+?(personal information)[a-z\\s]+?(account)\\?\\s?", "(should)[a-z\\s]+?(forget)[a-z\\s]+?(card'?s)[a-z\\s]+?(password)\\?\\s?", "(can)[a-z\\s]+?(withdraw)[a-z\\s]+?(cash)[a-z\\s]+?(card)\\?\\s?", "(can)[a-z\\s]+?(transfer)[a-z\\s]+?(money)[a-z\\s]+?(one card)[a-z\\s]+?(another)\\?\\s?", "(can)[a-z\\s]+?(check)[a-z\\s]+?(recent transactions)[a-z\\s]+?(card)\\?\\s?", "(should)[a-z\\s]+?(receive)[a-z\\s]+?(incorrect)[a-z\\s]+?(card statement)\\?\\s?", "(can)[a-z\\s]+?(set)[a-z\\s]+?(transaction limits)[a-z\\s]+?(card)\\?\\s?", "(can)[a-z\\s]+?(change)[a-z\\s]+?(card's PIN code)\\?\\s?", "(can)[a-z\\s]+?(set up)[a-z\\s]+?(transaction notifications)[a-z\\s]+?(card)\\?\\s?"};
        String simulationRegex = "^\\[Simulation]\\s";
        String questionRegex = "((how)?|(what)?)[a-z\\s]+?";
        boolean isCorrect = false;
        var output = outText.split("\n");

        if (output.length != 4) {//  ALWAYS = 4
            throw new WrongAnswer("Your program should print " + 4 + " lines but it printed " + output.length + " lines.");
        }

        if (!output[0].toLowerCase().startsWith("[simulation]")) {
            throw new WrongAnswer("The first line should always start with '[Simulation]'.");
        }

        var simulationFirstLineQuestion = output[0].substring(12, output[0].length() - 19).toLowerCase().trim(); //first chat line text

        for (String checkQuestion : questionsRegexes) {// first chat line checking

            var tmpReg = simulationRegex + questionRegex + checkQuestion + TIMEREGEX;
            if (Pattern.matches(tmpReg.toLowerCase(), output[0].toLowerCase().trim())) {

                var tmpReg2 = "^" + questionRegex + checkQuestion + "$";
                if (Pattern.matches(tmpReg2.toLowerCase(), simulationFirstLineQuestion)) {
                    isCorrect = true;
                    break;
                }
            }
        }
        if (!isCorrect) {
            throw new WrongAnswer("Incorrect question. Your program should print '" + simulationFirstLineQuestion + "' but it printed '" + output[0] + "'");
        }
        var connectOperatorRegex = sysMsgRegex + "Operator [a-z]{2,10} is connected " + TIMEREGEX; //second chat line regex
        if (!Pattern.matches(connectOperatorRegex.toLowerCase(), output[1].toLowerCase().trim())) {
            throw new WrongAnswer("Incorrect operator connection message.");
        }

        var getThirdMsgInLine = output[2].split(": "); // 1 - operator name 2 - operator response + time

        var response = getThirdMsgInLine[1].substring(0, getThirdMsgInLine[1].length() - 19).trim();
        var responseRegex = "[a-zA-Z!?,.\\-()\"\\s']+\\s?";

        var operatorName = getThirdMsgInLine[0].trim();
        var operatorNameRegex = "^[a-zA-Z]{2,10}:\\s?";

        var finalRegex = operatorNameRegex + responseRegex + TIMEREGEX; //third chat line regex


        if (!Pattern.matches(operatorNameRegex, operatorName + ": ") || !output[1].contains(operatorName)) {
            throw new WrongAnswer("Operator name '" + operatorName + "' is not correct orin one answer, the operator names do not match.\n" + "Check the lines: " + output[1] + " and \n" + output[2]);
        }
        if (40 > response.length() || response.length() > 140) {
            throw new WrongAnswer("Operator response '" + response + "' is too long");
        }
        if (!response.toLowerCase().replaceAll("[a-zA-Z!?,.\\-()\"\\s']", "").isEmpty()) {
            throw new WrongAnswer("Operator response '" + response + "' is not correct, because it contains illegal characters.");
        }

        if (!Pattern.matches(finalRegex, output[2].trim())) {
            throw new WrongAnswer("""
                    In your chat implementation, the operator's response does not match the requirements.
                    What the operator's response might look like:
                    '"Operator Name": "Operator response on simulation question" "dd-MM-yyyy HH:mm:ss"'
                    """);
        }

        var fourthMsgRegex = sysMsgRegex + "did you get an answers? to your questions?\\?" + yOrNRegex + TIMEREGEX;
        if (!Pattern.matches(fourthMsgRegex.toLowerCase(), output[3].toLowerCase().trim())) {
            throw new WrongAnswer("""
                                          The clarifying question that comes after the operator's answer does not meet the requirements.
                                          This line should look like this:
                                          System message: Did you get an answer to your question? "dd-MM-yyyy HH:mm:ss"
                                          """ + "But your line is printed '" + output[3] + "'");
        }
    }

    private void autoTestingChatAfterSimulation(String outputText) /* Contains test options for testing section 2. Chat Support - after the initialization of the simulation. */ {
        String yOrNRegex = "\\s?['\"(]y[,.\\s/]?n['\")]\\s?";
        String sysMsgRegex = "^System message: ";

        String sorryInChatMsgRegex = sysMsgRegex + "We'?re sorry,? but there are currently no available operators,? please contact us later\\.?\\s?-?";
        String askAnotherInChatMsgRegex = sysMsgRegex + "Ask another question\\?" + yOrNRegex;
        String completeInChatMsgRegex = sysMsgRegex + "Chat completed\\.?,? Redirecting to the main menu\\.?\\s?";
        var output = outputText.split("\n");
        boolean isCorrect = Pattern.matches(sorryInChatMsgRegex.toLowerCase() + TIMEREGEX, output[0].toLowerCase());

        if (Pattern.matches(completeInChatMsgRegex.toLowerCase() + TIMEREGEX, output[0].toLowerCase())) {
            isCorrect = true;
        }
        if (Pattern.matches(askAnotherInChatMsgRegex.toLowerCase() + TIMEREGEX, output[0].toLowerCase())) {
            isCorrect = true;
        }
        if (!isCorrect) {
            throw new WrongAnswer("""
                                          Your program in this chat line can only print one of the following messages: 'System message: Ask another question? (Y/N) dd-MM-yyyy HH:mm:ss,
                                          'System message: Chat completed, Redirecting to the main menu dd-MM-yyyy HH:mm:ss' or System message: We're sorry, but there are currently no available operators, please contact us later. dd-MM-yyyy HH:mm:ss
                                          """ + "' but printed '" + output[0] + "'");
        }
    }


    private final Object[] forAnyCase = /* Set of characters for testing any case */{"!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "=", "+", "[", "]", "{", "}", "|", "\\", ";", ":", "'", "\"", ",", ".", "<", ">", "/", "?", "`", "~", " ", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"};

    private String generatePassword(boolean isCheck)  /* Password generator method for testing, serves for a wide range of options, which is an ideal way in testing to eliminate repetitive tests. */ {

        StringBuilder passwordBuilder = new StringBuilder();
        int length = randomize(19) + 7;
        String output;
        while (true) {
            for (int i = 0; i < length; i++) {
                var forLoginNReg = forAnyCase[randomize(forAnyCase.length)];
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

    private boolean validatePassword(String password) /* Password validator helper method for the major generatePassword method.*/ {
        return password.length() >= 6 && password.length() <= 28 // Valid password length
               && password.replaceAll("[a-zA-Z\\d!@#$%\\s]", "").isEmpty() // Valid characters
               && password.matches(".*[A-Z].*") // At least one capital letter
               && password.matches(".*[a-z].*") // At least one lowercase letter
               && password.matches(".*\\d.*") // At least one digit
               && !password.matches("^\\s.*|^.*\\s$"); // Space start or end
    }

    private String generatePhone(boolean isCheck) /* Phone generator method for testing, serves for a wide range of options, which is an ideal way in testing to eliminate repetitive tests. */ {
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

    // Helper methods for the major generatePhone method {
    private String generateRandomDigits(int length) /* Digits generator*/ {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(randomize(10));
        }
        return sb.toString();
    }

    private String generateRandomAnyCase(int length) /* Any case generator  */ {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(forAnyCase[randomize(forAnyCase.length)]);
        }
        return sb.toString();
    }

    private boolean validatePhone(String phoneNumber) /* Phone validation  */ {
        // Checking all requirements
        Pattern pattern = Pattern.compile("^\\+?\\(?1\\)?[-\\s]?\\d{3}[-\\s]?\\d{3}[-\\s]?\\d{4}$");
        boolean isMatch = pattern.matcher(phoneNumber).matches();
        // Checking the length
        phoneNumber = phoneNumber.replaceAll("\\D", "");
        boolean lengthCase = phoneNumber.length() == 11;
        // result
        return isMatch && lengthCase;
    }
    // }

    private boolean verifyPassword(String password, byte[] salt, String hashedPassword) {
        byte[] enteredPasswordHash = hashPassword(password, salt);
        // Decode stored hashed password from Base64 format
        byte[] savedPasswordHash = Base64.getDecoder().decode(hashedPassword);
        return MessageDigest.isEqual(savedPasswordHash, enteredPasswordHash);
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

    private String parseExchangeRate(String responseBody, String currency) /* Currency exchange parser */ {
        String[] exchangeRate = responseBody.split("\"}");
        String res = null;
        for (var rate : exchangeRate) {
            if (rate.contains(currency)) {
                res = rate.replaceAll("[^\\d.]", "");
                break;
            }
        }
        return "Currency exchange: USD to " + currency + " exchange rate: " + res;
    }

    private String initLocalServer() {
        StringBuilder response = new StringBuilder();
        HttpURLConnection connection = null;
        int responseCode;
        try {
            connection = getHttpURLConnection();
            connection.setConnectTimeout(5000);
            connection.connect();
            responseCode = connection.getResponseCode();

            if (responseCode == HttpURLConnection.HTTP_OK) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
        return response.toString();
    }

    protected final String apiKey = "ASDcvv14Dfvv67539a551345n2l34kjklhv012";
    private HttpURLConnection getHttpURLConnection() {
        URL url;
        try {
            url = new URL("http://localhost:8080/hyperskill-exchange/api/latest.json?app_id=" + apiKey);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
        HttpURLConnection connection;
        try {
            connection = (HttpURLConnection) url.openConnection();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try {
            connection.setRequestMethod("GET");
        } catch (ProtocolException e) {
            throw new RuntimeException(e);
        }
        return connection;
    }

    private int randomize(int i) /* General randomizer */ {
        return random.nextInt(i);
    }
}
