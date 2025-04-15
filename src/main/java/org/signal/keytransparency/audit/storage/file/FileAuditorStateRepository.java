/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit.storage.file;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import jakarta.inject.Singleton;
import org.signal.keytransparency.audit.storage.AuditorStateRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

/**
 * An auditor state repository that uses a file as its backing store.
 */
@Singleton
@Requires(property = "storage.file.name")
public class FileAuditorStateRepository implements AuditorStateRepository {

  private static final Logger logger = LoggerFactory.getLogger(FileAuditorStateRepository.class);
  private final String fileName;

  public FileAuditorStateRepository(@Property(name = "storage.file.name") String fileName) {
    this.fileName = fileName;
  }

  @Override
  public Optional<byte[]> getAuditorStateAndSignature() throws IOException {
    try (final FileInputStream fileInputStream = new FileInputStream(fileName)) {
      return Optional.of(fileInputStream.readAllBytes());
    } catch (final FileNotFoundException e) {
      logger.info("Auditor state data not found");
      return Optional.empty();
    } catch (final IOException e) {
      logger.error("Unexpected error reading auditor state data", e);
      throw e;
    }
  }

  @Override
  public void storeAuditorStateAndSignature(byte[] serializedAuditorStateAndSignature) throws IOException {
    try {
      // recursively create parent directories if they don't already exist
      final Path path = Paths.get(fileName).getParent();
      if (path != null) {
        Files.createDirectories(path);
      }
      try (final FileOutputStream fileOutputStream = new FileOutputStream(fileName)) {
        fileOutputStream.write(serializedAuditorStateAndSignature);
      }
    } catch (final IOException e) {
      logger.error("Unexpected error writing auditor state data", e);
      throw e;
    }
  }
}
