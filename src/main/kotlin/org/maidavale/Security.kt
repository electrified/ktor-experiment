package org.maidavale

import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.request.headers
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.URLBuilder
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.OAuthAccessTokenResponse
import io.ktor.server.auth.OAuthServerSettings
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.oauth
import io.ktor.server.auth.principal
import io.ktor.server.html.respondHtml
import io.ktor.server.request.uri
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.cookie
import io.ktor.server.sessions.get
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import kotlinx.html.a
import kotlinx.html.body
import kotlinx.html.p
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

val applicationHttpClient = HttpClient(CIO) {
    install(ContentNegotiation) {
        json()
    }
}


fun Application.configureSecurity(httpClient: HttpClient = applicationHttpClient) {
    install(Sessions) {
        cookie<UserSession>("user_session")
    }
//    install(CSRF) {
//        // tests Origin is an expected value
//        allowOrigin("http://localhost:8080")
//
//        // tests Origin matches Host header
//        originMatchesHost()
//
//        // custom header checks
//        checkHeader("X-CSRF-Token")
//    }
//    // Please read the jwt property from the config file if you are using EngineMain
//    val jwtAudience = "jwt-audience"
//    val jwtDomain = "https://jwt-provider-domain/"
//    val jwtRealm = "ktor sample app"
//    val jwtSecret = "secret"
//    authentication {
//        jwt {
//            realm = jwtRealm
//            verifier(
//                JWT
//                    .require(Algorithm.HMAC256(jwtSecret))
//                    .withAudience(jwtAudience)
//                    .withIssuer(jwtDomain)
//                    .build()
//            )
//            validate { credential ->
//                if (credential.payload.audience.contains(jwtAudience)) JWTPrincipal(credential.payload) else null
//            }
//        }
//    }

    val redirects = mutableMapOf<String, String>()
    install(Authentication) {
        oauth("keycloak") {
            // Configure oauth authentication
            urlProvider = { "http://localhost:8024/callback" }
            providerLookup = {
                OAuthServerSettings.OAuth2ServerSettings(
                    name = "keycloak",
                    authorizeUrl = "http://localhost:8080/realms/test/protocol/openid-connect/auth",
                    accessTokenUrl = "http://localhost:8080/realms/test/protocol/openid-connect/token",
                    requestMethod = HttpMethod.Post,
                    clientId = System.getenv("CLIENT_ID"),
                    clientSecret = System.getenv("CLIENT_SECRET"),
                    defaultScopes = listOf("openid", "basic"),
//                    extraAuthParameters = listOf("access_type" to "offline"),
                    onStateCreated = { call, state ->
                        //saves new state with redirect url value
                        call.request.queryParameters["redirectUrl"]?.let {
                            redirects[state] = it
                        }
                    }
                )
            }
            client = httpClient
        }
    }

    routing {
        authenticate("keycloak") {
            get("/login") {
                // Redirects to 'authorizeUrl' automatically
            }

            get("/callback") {
                val currentPrincipal: OAuthAccessTokenResponse.OAuth2? = call.principal()
                // redirects home if the url is not found before authorization
                currentPrincipal?.let { principal ->
                    principal.state?.let { state ->
                        call.sessions.set(UserSession(state, principal.accessToken))
                        redirects[state]?.let { redirect ->
                            call.respondRedirect(redirect)
                            return@get
                        }
                    }
                }
                call.respondRedirect("/home")
            }
        }
        get("/") {
            call.respondHtml {
                body {
                    p {
                        a("/login") { +"Login with Google" }
                    }
                }
            }
        }
        get("/home") {
            val userSession: UserSession? = getSession(call)
            if (userSession != null) {
                val userInfo: UserInfo = getPersonalGreeting(httpClient, userSession)
                call.respondText("Hello, ${userInfo.name}! Welcome home!")
            }
        }
        get("/{path}") {
            val userSession: UserSession? = getSession(call)
            if (userSession != null) {
                val userInfo: UserInfo = getPersonalGreeting(httpClient, userSession)
                call.respondText("Hello, ${userInfo.name}!")
            }
        }
    }
}

private suspend fun getPersonalGreeting(
    httpClient: HttpClient,
    userSession: UserSession
): UserInfo = httpClient.get("http://localhost:8080/realms/test/protocol/openid-connect/userinfo") {
    headers {
        append(HttpHeaders.Authorization, "Bearer ${userSession.token}")
    }
}.body()

private suspend fun getSession(
    call: ApplicationCall
): UserSession? {
    val userSession: UserSession? = call.sessions.get()
    //if there is no session, redirect to login
    if (userSession == null) {
        val redirectUrl = URLBuilder("http://0.0.0.0:8024/login").run {
            parameters.append("redirectUrl", call.request.uri)
            build()
        }
        call.respondRedirect(redirectUrl)
        return null
    }
    return userSession
}


@Serializable
data class UserSession(val state: String, val token: String)

@Serializable
data class UserInfo(
    val sub: String,
    val name: String,
    @SerialName("given_name") val givenName: String,
    @SerialName("family_name") val familyName: String,
    @SerialName("email_verified")val emailVerified: Boolean,
    @SerialName("preferred_username")val preferredUsername: String,
    val email: String,
)

