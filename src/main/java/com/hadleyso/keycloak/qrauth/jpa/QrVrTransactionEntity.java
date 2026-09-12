package com.hadleyso.keycloak.qrauth.jpa;

import jakarta.persistence.*;

import java.util.Date;

@Entity
@Table(
    name = "AO_HADLEYSO_QR_VR_TRANSACTION",
    indexes = {
        @Index(
            name = "IDX_QR_VR_TOKEN_HASH",
            columnList = "TOKEN_HASH",
            unique = true
        ),
        @Index(
            name = "IDX_QR_VR_USER_ID",
            columnList = "USER_ID"
        ),
        @Index(
            name = "IDX_QR_VR_EXPIRES_AT",
            columnList = "EXPIRES_AT"
        )
    }
)
public class QrVrTransactionEntity {

    @Id
    @Column(name = "TRANSACTION_ID", length = 64, nullable = false)
    private String transactionId;

    @Column(name = "REALM_ID", length = 255, nullable = false)
    private String realmId;

    @Column(name = "USER_ID", length = 255, nullable = false)
    private String userId;

    @Column(name = "CLIENT_ID", length = 255, nullable = false)
    private String clientId;

    @Column(name = "TOKEN_HASH", length = 64, nullable = false, unique = true)
    private String tokenHash;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "CREATED_AT", nullable = false)
    private Date createdAt;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "EXPIRES_AT", nullable = false)
    private Date expiresAt;

    @Column(name = "USED", nullable = false)
    private boolean used = false;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = new Date();
        }
    }

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public void setTokenHash(String tokenHash) {
        this.tokenHash = tokenHash;
    }

    public Date getCreatedAt() {
        return createdAt;
    }

    public Date getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Date expiresAt) {
        this.expiresAt = expiresAt;
    }

    public boolean isUsed() {
        return used;
    }

    public void setUsed(boolean used) {
        this.used = used;
    }
}