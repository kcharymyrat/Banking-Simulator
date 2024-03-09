package banking;

public class Rate {
    private String base;
    private String usd;

    public Rate(String base, String usd) {
        this.base = base;
        this.usd = usd;
    }

    public String getBase() {
        return base;
    }

    public void setBase(String base) {
        this.base = base;
    }

    public String getUsd() {
        return usd;
    }

    public void setUsd(String usd) {
        this.usd = usd;
    }

    @Override
    public String toString() {
        return "Rate{" +
                "base='" + base + '\'' +
                ", usd='" + usd + '\'' +
                '}';
    }
}
