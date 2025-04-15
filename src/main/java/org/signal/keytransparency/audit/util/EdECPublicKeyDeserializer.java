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
import java.security.interfaces.EdECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

@Prototype
class EdECPublicKeyDeserializer implements TypeConverter<String, EdECPublicKey> {

  @Override
  public Optional<EdECPublicKey> convert(final String base64, final Class<EdECPublicKey> targetType,
      final ConversionContext context) {
    try {
      final KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
      final byte[] publicKeyBytes = Base64.getDecoder().decode(base64);
      return Optional.of((EdECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes)));
    } catch (final InvalidKeySpecException | NoSuchAlgorithmException | IllegalArgumentException e) {
      context.reject(base64, e);
      return Optional.empty();
    }
  }
}
