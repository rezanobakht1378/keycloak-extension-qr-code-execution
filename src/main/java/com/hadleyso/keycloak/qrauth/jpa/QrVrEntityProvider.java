package com.hadleyso.keycloak.qrauth.jpa;

import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;

import java.util.Collections;
import java.util.List;

public class QrVrEntityProvider implements JpaEntityProvider {

    @Override
    public List<Class<?>> getEntities() {
        return Collections.singletonList(
            QrVrTransactionEntity.class
        );
    }

    @Override
    public String getChangelogLocation() {
        return "META-INF/jpa-changelog-qr-vr.xml";
    }

    @Override
    public String getFactoryId() {
        return QrVrEntityProviderFactory.ID;
    }

    @Override
    public void close() {
    }
}