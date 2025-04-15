/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit.util;

import io.micronaut.context.annotation.Prototype;
import io.micronaut.core.convert.ConversionContext;
import io.micronaut.core.convert.TypeConverter;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

@Prototype
class EdECPrivateKeyDeserializer implements TypeConverter<String, EdECPrivateKey> {

  @Override
  public Optional<EdECPrivateKey> convert(final String base64, final Class<EdECPrivateKey> targetType,
      final ConversionContext context) {
    try {
      final KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
      final byte[] privateKeyBytes = Base64.getDecoder().decode(base64);
      return Optional.of((EdECPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes)));
    } catch (final InvalidKeySpecException | NoSuchAlgorithmException | IllegalArgumentException e) {
      context.reject(base64, e);
      return Optional.empty();
    }
  }
}
