import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * SampleServer - a deliberately minimal Java HTTP service for testing
 * java4shell-check.
 *
 * It decodes the Base64 part of an HTTP Basic Authorization header on every
 * request - the classic pre-auth path described in the Java4Shell write-up.
 *
 * Note the response behavior: it tells you whether the input was decoded or
 * rejected. That is exactly why HTTP responses CANNOT distinguish a patched
 * from an unpatched JVM: malformed trigger inputs are rejected by BOTH - the
 * corruption on vulnerable builds happens before the rejection, invisibly
 * in the heap. The HTTP layer has no oracle.
 *
 * Run:  java SampleServer.java [port]     (listens on 5000 by default)
 */
public class SampleServer {
    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 5000;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", (HttpExchange ex) -> {
            String auth = ex.getRequestHeaders().getFirst("Authorization");
            String status = "no-auth";
            if (auth != null && auth.startsWith("Basic ")) {
                try {
                    Base64.getDecoder().decode(auth.substring(6));
                    status = "decoded";
                } catch (IllegalArgumentException e) {
                    // App swallows the exception - the HTTP response shape is
                    // identical on patched and unpatched JVMs.
                    status = "rejected";
                }
            }
            byte[] body = status.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        });
        server.start();
        System.out.println("SampleServer listening on :" + port);
        Thread.currentThread().join();
    }
}
