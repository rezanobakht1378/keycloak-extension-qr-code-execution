package com.hadleyso.keycloak.qrauth.resources;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.HttpHeaders;

import org.jboss.logging.Logger;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;

import com.hadleyso.keycloak.qrauth.jpa.QrVrTransactionEntity;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import org.keycloak.events.EventBuilder;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.UserSessionModel;

public class QrVrResourceProvider
        implements RealmResourceProvider {

    private static final Logger LOG =
            Logger.getLogger(QrVrResourceProvider.class);

    private static final String VR_CLIENT_ID = "cognick-vr";

    private static final long QR_TTL_SECONDS = 60;

    private static final SecureRandom SECURE_RANDOM =
            new SecureRandom();

    private final KeycloakSession session;

    public QrVrResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
    }

    @POST
    @Path("start")
    // @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response start() {

        RealmModel realm =
                session.getContext().getRealm();

        if (realm == null) {
            return error(
                    Response.Status.BAD_REQUEST,
                    "REALM_NOT_FOUND",
                    "Realm was not found."
            );
        }

        /*
         * Authenticate the caller using the Keycloak
         * identity/session cookie.
         */
        AppAuthManager.BearerTokenAuthenticator bearerAuthenticator =
                new AppAuthManager.BearerTokenAuthenticator(session);

        AuthenticationManager.AuthResult authResult;

        try {

                authResult = bearerAuthenticator.authenticate();

        } catch (Exception e) {

                LOG.warnf(
                        e,
                        "Bearer token authentication failed"
                );

                return error(
                        Response.Status.UNAUTHORIZED,
                        "INVALID_TOKEN",
                        "The bearer token is invalid or expired."
                );
        }

        if (authResult == null ||
                authResult.getUser() == null) {

                return error(
                        Response.Status.UNAUTHORIZED,
                        "NOT_AUTHENTICATED",
                        "Bearer token did not resolve to a user."
                );
        }

        UserModel user =
                authResult.getUser();

        /*
         * Make sure the target VR client exists.
         */
        ClientModel vrClient =
                realm.getClientByClientId(
                        VR_CLIENT_ID
                );

        if (vrClient == null) {

            LOG.errorf(
                    "VR client '%s' does not exist in realm '%s'",
                    VR_CLIENT_ID,
                    realm.getName()
            );

            return error(
                    Response.Status.INTERNAL_SERVER_ERROR,
                    "VR_CLIENT_NOT_FOUND",
                    "VR client is not configured."
            );
        }

        /*
         * Generate transaction ID.
         */
        String transactionId =
                UUID.randomUUID().toString();

        /*
         * Generate a cryptographically secure
         * random QR token.
         */
        String qrToken =
                generateSecureToken(32);

        /*
         * Store only SHA-256(token).
         */
        String tokenHash =
                sha256(qrToken);

        Date createdAt =
                new Date();

        Date expiresAt =
                new Date(
                        createdAt.getTime()
                                + QR_TTL_SECONDS * 1000L
                );

        /*
         * Persist transaction.
         */
        QrVrTransactionEntity transaction =
                new QrVrTransactionEntity();

        transaction.setTransactionId(
                transactionId
        );

        transaction.setRealmId(
                realm.getId()
        );

        transaction.setUserId(
                user.getId()
        );

        transaction.setClientId(
                VR_CLIENT_ID
        );

        transaction.setTokenHash(
                tokenHash
        );

        transaction.setExpiresAt(
                expiresAt
        );

        transaction.setUsed(false);

        EntityManager em =
                session
                        .getProvider(
                                JpaConnectionProvider.class
                        )
                        .getEntityManager();

        em.persist(transaction);

        /*
         * Build the URL which will eventually
         * be scanned by the VR application.
         */
        String baseUri =
                session
                        .getContext()
                        .getUri()
                        .getBaseUri()
                        .toString();

        if (!baseUri.endsWith("/")) {
            baseUri += "/";
        }

        String qrUrl =
                baseUri
                        + "realms/"
                        + realm.getName()
                        + "/qr-vr/scan/"
                        + qrToken;

        LOG.infof(
                "Created VR QR transaction. transactionId=%s userId=%s clientId=%s",
                transactionId,
                user.getId(),
                VR_CLIENT_ID
        );

        return Response
                .ok(
                        new StartQrResponse(
                                transactionId,
                                qrToken,
                                qrUrl,
                                QR_TTL_SECONDS
                        )
                )
                .build();
    }

    @GET
    @Path("scan/{token}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response scan(
            @PathParam("token") String token
    ) {
        RealmModel realm =
                session.getContext().getRealm();

        if (realm == null || token == null || token.isBlank()) {
            return error(
                    Response.Status.BAD_REQUEST,
                    "INVALID_QR_CODE",
                    "The QR code is invalid."
            );
        }

        EntityManager em =
                session
                        .getProvider(
                                JpaConnectionProvider.class
                        )
                        .getEntityManager();

        String tokenHash =
                sha256(token);

        QrVrTransactionEntity transaction =
                em.createQuery(
                                "select t from QrVrTransactionEntity t "
                                        + "where t.tokenHash = :tokenHash "
                                        + "and t.realmId = :realmId",
                                QrVrTransactionEntity.class
                        )
                        .setParameter("tokenHash", tokenHash)
                        .setParameter("realmId", realm.getId())
                        .setLockMode(LockModeType.PESSIMISTIC_WRITE)
                        .getResultList()
                        .stream()
                        .findFirst()
                        .orElse(null);

        if (transaction == null) {
            return error(
                    Response.Status.NOT_FOUND,
                    "QR_CODE_NOT_FOUND",
                    "The QR code is invalid or has expired."
            );
        }

        if (transaction.getExpiresAt().before(new Date())) {
            return error(
                    Response.Status.GONE,
                    "QR_CODE_EXPIRED",
                    "The QR code has expired."
            );
        }

        if (transaction.isUsed()) {
            return error(
                    Response.Status.CONFLICT,
                    "QR_CODE_USED",
                    "The QR code has already been used."
            );
        }

        UserModel user =
                session
                        .users()
                        .getUserById(
                                realm,
                                transaction.getUserId()
                        );

        ClientModel vrClient =
                realm.getClientByClientId(
                        transaction.getClientId()
                );

        if (user == null || vrClient == null) {
            return error(
                    Response.Status.NOT_FOUND,
                    "QR_CODE_TARGET_NOT_FOUND",
                    "The QR code target is no longer available."
            );
        }

        session
                .getContext()
                .setClient(vrClient);

        UserSessionModel userSession =
                session
                        .sessions()
                        .createUserSession(
                                realm,
                                user,
                                "qr-vr",
                                null,
                                null,
                                false,
                                null,
                                null
                        );

        AuthenticatedClientSessionModel clientSession =
                session
                        .sessions()
                        .createClientSession(
                                realm,
                                vrClient,
                                userSession
                        );

        DefaultClientSessionContext clientSessionContext =
                DefaultClientSessionContext
                        .fromClientSessionScopeParameter(
                                clientSession,
                                session
                        );

        EventBuilder event =
                new EventBuilder(
                        realm,
                        session
                )
                        .client(vrClient)
                        .user(user)
                        .session(userSession);

        AccessTokenResponse tokenResponse =
                new TokenManager()
                        .responseBuilder(
                                realm,
                                vrClient,
                                event,
                                session,
                                userSession,
                                clientSessionContext
                        )
                        .generateAccessToken()
                        .generateRefreshToken()
                        .build();

        transaction.setUsed(true);

        return Response
                .ok(tokenResponse)
                .build();
    }

    private static String generateSecureToken(
            int numberOfBytes
    ) {

        byte[] bytes =
                new byte[numberOfBytes];

        SECURE_RANDOM.nextBytes(bytes);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }

    private static String sha256(
            String value
    ) {

        try {

            MessageDigest digest =
                    MessageDigest.getInstance(
                            "SHA-256"
                    );

            byte[] hash =
                    digest.digest(
                            value.getBytes(
                                    StandardCharsets.UTF_8
                            )
                    );

            return Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(hash);

        } catch (NoSuchAlgorithmException e) {

            throw new IllegalStateException(
                    "SHA-256 algorithm is not available",
                    e
            );
        }
    }

    private Response error(
            Response.Status status,
            String code,
            String message
    ) {

        return Response
                .status(status)
                .entity(
                        new ErrorResponse(
                                code,
                                message
                        )
                )
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    public record StartQrResponse(
            String transaction_id,
            String qr_token,
            String qr_url,
            long expires_in
    ) {
    }

    public record ScanQrResponse(
            String transaction_id,
            Date expires_at
    ) {
    }

    public record ErrorResponse(
            String error,
            String message
    ) {
    }
}