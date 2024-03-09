package banking;

import java.time.LocalDateTime;
import java.util.ArrayList;

public class UserDetail {
    private String login;
    private String password;
    private String salt;
    private LocalDateTime registrationTime;
    private LocalDateTime lastAuthorizationSession;
    private ArrayList<LocalDateTime> access;

    public UserDetail() {
    }

    public UserDetail(String login, String password, String salt,
                      LocalDateTime registrationTime, LocalDateTime lastAuthorizationSession,
                      ArrayList<LocalDateTime> access) {
        this.login = login;
        this.password = password;
        this.salt = salt;
        this.registrationTime = registrationTime;
        this.lastAuthorizationSession = lastAuthorizationSession;
        this.access = access;
    }

    // Getters
    public String getLogin() {
        return login;
    }

    public String getPassword() {
        return password;
    }

    public String getSalt() {
        return salt;
    }

    public LocalDateTime getRegistrationTime() {
        return registrationTime;
    }

    public LocalDateTime getLastAuthorizationSession() {
        return lastAuthorizationSession;
    }

    public ArrayList<LocalDateTime> getAccess() {
        return access;
    }

    // Setters
    public void setLogin(String login) {
        this.login = login;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public void setRegistrationTime(LocalDateTime registrationTime) {
        this.registrationTime = registrationTime;
    }

    public void setLastAuthorizationSession(LocalDateTime lastAuthorizationSession) {
        this.lastAuthorizationSession = lastAuthorizationSession;
    }

    public void setAccess(ArrayList<LocalDateTime> access) {
        this.access = access;
    }

    public void addToAccess(LocalDateTime invalid) {
        if (this.access.size() < 3) {
            this.access.add(invalid);
        } else {
            this.access.remove(0);
            this.access.add(invalid);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("UserDetail {");
        sb.append("\n\tlogin : ").append(login).append(", ");
        sb.append("\n\tpassword : ").append(password).append(", ");
        sb.append("\n\tsalt : ").append(salt).append(", ");
        sb.append("\n\tregistrationTime : ").append(registrationTime).append(", ");
        sb.append("\n\tlastAuthorizationSession : ").append(lastAuthorizationSession).append(", ");
        sb.append("\n\taccess : ").append(getAccess());
        sb.append("\n}");
        return sb.toString();
    }
}
