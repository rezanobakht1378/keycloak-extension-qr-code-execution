package com.hadleyso.keycloak.qrauth.jpa;

import org.keycloak.Config.Scope;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class QrVrEntityProviderFactory
        implements JpaEntityProviderFactory {

    public static final String ID =
            "com-hadleyso-keycloak-qr-vr";

    @Override
    public JpaEntityProvider create(KeycloakSession session) {
        return new QrVrEntityProvider();
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void init(Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}