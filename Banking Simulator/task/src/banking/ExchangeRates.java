package banking;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ExchangeRates {

    static String url = "http://localhost:8080/hyperskill-exchange/api/latest.json?app_id=ASDcvv14Dfvv67539a551345n2l34kjklhv012";
    static HttpResponse<String>  getExchangeResponse() {
        HttpClient httpClient = HttpClient.newHttpClient();

        URI exchangeWebAddress = URI.create(url);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(exchangeWebAddress)
                .GET()
                .build();

        try {
            return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            System.out.println("We cannot access the site. Please, try later.");
            return null;
        }
    }

    static List<Rate> parseResponse(HttpResponse<String> response) {
        List<Rate> rateList = new ArrayList<>();

        if (response == null || response.statusCode() != 200) {
            return null;
        }
        String resBody = response.body();
        // {"rates":{"USD":0.991},"base":"EUR"}
        // {"rates":{"USD":0.762},"base":"GBP"}
        // {"rates":{"USD":36.669},"base":"UAH"}
        // {"rates":{"USD":7.135},"base":"CNY"}

        List<String> responseRates = List.of(resBody.split("\\n"));

        for (String rate : responseRates) {
            List<String> subStrList = List.of(rate.trim()
                    .replaceAll("\\{\"rates\":.*\"USD\":", "")
                    .replaceAll("},\"base\":\"", " ")
                    .replaceAll("\"}", "")
                    .split(" "));
            // System.out.println(subStrList);
            rateList.add(new Rate(subStrList.get(1).trim(), subStrList.get(0).trim()));
        }
        // System.out.println(rateList);
        return rateList;
    }

    static Rate getRate(List<Rate> rateList, String currency) {
        return rateList.stream()
                .filter(rate -> rate.getBase().equalsIgnoreCase(currency.trim()))
                .findFirst()
                .orElse(null);
    }
}
