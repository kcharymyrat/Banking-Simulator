package banking;

public class Validators {

    public static boolean isValidPhoneNumber(String phoneNumber) {
        String pattern = "^\\+?1?(?:-?\\(\\d{1,3}\\)-?|\\s?\\d{1,3}(?:-?\\d{3}){3})$";
        return phoneNumber.matches(pattern);
    }

    public static boolean isValidPassword(String password) {
        String pattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d!@#$%]+(\\s?[a-zA-Z\\d!@#$%]+)*$";
        return password.matches(pattern) && password.length() >= 6 && password.length() <= 28;
    }
}
