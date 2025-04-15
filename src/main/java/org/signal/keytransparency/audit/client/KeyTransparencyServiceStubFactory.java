/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit.client;

import io.grpc.ManagedChannel;
import io.micronaut.context.annotation.Factory;
import io.micronaut.grpc.annotation.GrpcChannel;
import jakarta.inject.Singleton;

@Factory
class KeyTransparencyServiceStubFactory {

  @Singleton
  KeyTransparencyServiceGrpc.KeyTransparencyServiceBlockingStub keyTransparencyServiceClient(
      @GrpcChannel("key-transparency") ManagedChannel managedChannel) {
    return KeyTransparencyServiceGrpc.newBlockingStub(managedChannel);
  }
}
