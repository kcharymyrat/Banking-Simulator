import org.hyperskill.hstest.dynamic.DynamicTest;
import org.hyperskill.hstest.exception.outcomes.WrongAnswer;
import org.hyperskill.hstest.stage.StageTest;
import org.hyperskill.hstest.testcase.CheckResult;
import org.hyperskill.hstest.testing.TestedProgram;

import java.util.Random;
import java.util.regex.Pattern;

import static org.hyperskill.hstest.testing.expect.Expectation.expect;

public class MainBankTest extends StageTest<String> {
    private TestedProgram main;

    @DynamicTest()
    CheckResult test1() {
        var username = "Alex";
        var password = "GreatAlexander2001";

        defaultStart(username, password);

        String output = main.execute(username);
        testingIsCorrectOutput("Password:", 1, 1, output);

        output = main.execute(password);
        testingIsCorrectOutput("Congratulations on your successful registration!", 1, 1, output);
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program must be should finished!");
        }
        return CheckResult.correct();
    }

    @DynamicTest
    CheckResult test2() {
        var username = "Jack";
        var password = "Jack$master$";

        defaultStart(username, password);

        String output = main.execute(username);
        testingIsCorrectOutput("Password:", 1, 1, output);

        output = main.execute(password.substring(0, password.length() - 1));
        testingIsCorrectOutput("Password doesn't match.", 1, 1, output);
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program must be should finished!");
        }
        return CheckResult.correct();
    }

    @DynamicTest(repeat = 10)
    CheckResult test3() {
        var username = "Jack";
        var password = "Jack";

        defaultStart(username, password);

        String output = main.execute(username + new Random().nextInt(100));
        testingIsCorrectOutput("Password:", 1, 1, output);

        output = main.execute(new Random().nextInt(100) + "Bad" + password);
        testingIsCorrectOutput("Username and password don't match.", 1, 1, output);
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program must be should finished!");
        }
        return CheckResult.correct();
    }

    @DynamicTest
    CheckResult test4() {
        var username = "Andy";
        var password = "Andy$master$";

        defaultStart(username, password);

        String output = main.execute(username + new Random().nextInt(100));
        testingIsCorrectOutput("Password:", 1, 1, output);

        output = main.execute(password);
        testingIsCorrectOutput("Username doesn't match.", 1, 1, output);
        if (!main.isFinished()) {
            throw new WrongAnswer("Your program must be should finished!");
        }
        return CheckResult.correct();
    }

    private void testingIsCorrectOutput(String correctOutput, int correctNumberOfLines, int testableOutputTextOnLineNumbered, String output) {
        String[] regexes = getStrings();

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

    private static String[] getStrings() {
        String looseTestes = "[!.]?$";
        String looseTestes2 = "(don['`]?t)|(doesn['`]?t)";
        return new String[]{"^enter[a-z\\s]+?again[a-z\\s]+?complete[a-z\\s]+?registrations?" + looseTestes //0
                , "^passwords? " + looseTestes2 + " match" + looseTestes //1
                , "^usernames? " + looseTestes2 + " match" + looseTestes //2
                , "^usernames? and passwords? " + looseTestes2 + " match" + looseTestes,   //3
                "^congratulations? on your? successful registrations?" + looseTestes, //4
                "^username:$", //5
                "^password:$", //6
        };
    }

    private void defaultStart(String username, String password) {
        main = new TestedProgram();
        String output = main.start();
        testingIsCorrectOutput("Username:", 1, 1, output);

        output = main.execute(username);
        testingIsCorrectOutput("Password:", 1, 1, output);

        output = main.execute(password);
        testingIsCorrectOutput("Enter the data again to complete the registration.", 2, 1, output);
        testingIsCorrectOutput("Username:", 2, 2, output);
    }
}