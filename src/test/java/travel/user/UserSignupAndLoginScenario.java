package travel.user;

import com.auth0.jwt.JWT;
import com.auth0.jwt.impl.JWTParser;
import com.thoughtworks.gauge.Step;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

public class UserSignupAndLoginScenario {

    private String username;
    private String password;
    private String jwtString;

    @Step("Signup user <username> with password <password>")
    public void signupNewUser(String username, String password) throws IOException, InterruptedException {
        this.username = username;
        this.password = password;
        var request = HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofString(getPayload()))
                .uri(URI.create("http://localhost:8081/user/signup"))
                .header("Content-Type", "application/json")
                .header("Accept", "*/*")
                .header("Accept-Encoding", "gzip, deflate, br")
                .build();
        var client = getClient();
        var response = client.send(request, HttpResponse.BodyHandlers.discarding());
        assertThat(response.statusCode()).isEqualTo(204);
    }

    private String getPayload() {
        return "{" +
                "\"username\":\"" + username + "\"," +
                "\"password\":\"" + password + "\"" +
                "}";
    }

    private HttpClient getClient() {
        return HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    @Step("Login new client")
    public void loginNewUser() throws IOException, InterruptedException {
        var request = HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofString(getPayload()))
                .uri(URI.create("http://localhost:8081/user/login"))
                .header("Content-Type", "application/json")
                .header("Accept", "text/plain")
                .header("Accept-Encoding", "gzip, deflate, br")
                .build();
        var client = getClient();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        jwtString = response.body();
        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Step("JWT is of user <username> and has role <role>")
    public void validateJwt(String username, String role) {
        var jwt = JWT.decode(jwtString);
        assertThat(jwt.getSubject()).isEqualTo(username);
        assertThat(jwt.getClaim("role").asString()).isEqualTo("USER");
        var exp = jwt.getClaim("exp").asLong();
        var nbf = jwt.getClaim("nbf").asLong();
        var iat = jwt.getClaim("iat").asLong();
        assertThat(iat).isEqualTo(nbf);
        assertThat(exp - nbf).isEqualTo(3600L);
    }
}
