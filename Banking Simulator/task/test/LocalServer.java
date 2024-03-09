import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Random;

public class LocalServer { //Create local server for testing
    private final StringBuilder responseBuilder = new StringBuilder();
    public final String CONFIRM = "ASDcvv14Dfvv67539a551345n2l34kjklhv012";

    public LocalServer(){
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
            server.createContext("/hyperskill-exchange/api", new CurrencyExchangeHandler());
            server.setExecutor(Runnable::run);
            server.start();

            for (String s : Arrays.asList("EUR", "GBP", "UAH", "CNY")) {
                responseBuilder.append(getFakeApiResponse(s)).append("\n");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String getFakeApiResponse(String currency) {
        String num;
        if (currency.equalsIgnoreCase("EUR")) {
            num = "0.9" + (random(49) + 49);
        } else if (currency.equalsIgnoreCase("GBP")) {
            num = "0.7" + (random(59) + 39);
        } else if (currency.equalsIgnoreCase("UAH")) {
            num = "36." + (random(599) + 399);
        } else {
            num = "7." + (random(100) + 99);
        }
        return String.format("{\"rates\":{\"USD\":%s},\"base\":\"%s\"}", num, currency);
    }

    private int random(int range) {
        return new Random().nextInt(range);
    }

    private class CurrencyExchangeHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String[] uris = exchange.getRequestURI().toString().split("/");

            if (uris.length == 4) {
                String apiKey = uris[uris.length - 1].replace("latest.json?app_id=", "");
                if (uris[3].startsWith("latest.json") && apiKey.equals(CONFIRM)) {
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    String response = responseBuilder.toString();
                    exchange.sendResponseHeaders(200, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                } else {
                    String response = "Invalid key: " + apiKey;
                    exchange.sendResponseHeaders(404, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            } else {
                String response = "Invalid request";
                exchange.sendResponseHeaders(400, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
        }
    }
}
