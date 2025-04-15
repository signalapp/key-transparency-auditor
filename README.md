key-transparency-auditor
========================

A reference implementation of a third-party auditor for Signal's key transparency service, based on the [key transparency](https://bren2010.github.io/draft-key-transparency/draft-mcmillion-key-transparency.html) specification.

Overview
--------

This service is written in Java using the [Micronaut](https://docs.micronaut.io/4.4.10/guide/) framework. To build and unit test, run

```shell
./mvnw clean test
```
in the root directory.

The main class is the [`Auditor`](./src/main/java/org/signal/keytransparency/audit/Auditor.java), which runs a scheduled job that requests a
stream of updates from the key transparency service. It maintains a condensed view of the key transparency service's [prefix tree](https://bren2010.github.io/draft-key-transparency/draft-mcmillion-key-transparency.html#name-prefix-tree)
and [log tree](https://bren2010.github.io/draft-key-transparency/draft-mcmillion-key-transparency.html#name-log-tree),
storing just enough information to verify and accept each update sequentially. If the auditor has processed a certain number of updates or a certain amount of time has elapsed, the auditor sends back a 
[signed tree head](https://bren2010.github.io/draft-key-transparency/draft-mcmillion-key-transparency.html#name-tree-head-signature)
to the key transparency service, indicating that its view of the prefix and log trees up to the given update matches. 
If the remote call succeeds, the auditor writes its state data to an [`AuditorStateRepository`](./src/main/java/org/signal/keytransparency/audit/storage/AuditorStateRepository.java),
which it may use to resume from its most recent position in the key transparency log if the auditor is restarted.

If the auditor encounters an inconsistency in verifying an update, it throws an `InvalidProofException` and stops
sending signed tree heads back to the key transparency service.

Configuration
-------------

The service needs `Auditor`, `KeyTransparencyServiceClient`, and `AuditorStateRepository` beans to run.
The table below describes the [configuration](https://docs.micronaut.io/latest/guide/#configurationProperties) [properties](https://docs.micronaut.io/latest/guide/#valueAnnotation) necessary to instantiate those beans.


| Property                                              | Required?                                        | Description                                                                                                                                                                                                                                                                                 |
|-------------------------------------------------------|--------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `auditor.private-key`                                 | yes                                              | A PKCS#8-formatted Ed25519 private key encoded in standard base64 and used to sign the tree head sent back to the key transparency service. Can be generated via `openssl genpkey -algorithm ed25519` and discarding the PEM header and footer.                                             |
| `auditor.public-key`                                  | yes                                              | A X509-formatted Ed25519 public key encoded in standard base64 that is the counterpart to `auditor.private-key`.                                                                                                                                                                            |
| `auditor.key-transparency-service-signing-public-key` | yes                                              | A PKCS#8-formatted Ed25519 public key encoded in standard base64 and used by clients to verify the key transparency service's signature over the tree head.                                                                                                                                 |
| `auditor.key-transparency-service-vrf-public-key`     | yes                                              | A PKCS#8-formatted Ed25519 public key encoded in standard base64 and used by clients to verify that the input to a [Verifiable Random Function](https://www.rfc-editor.org/rfc/rfc9381.html) (requested search key) matches the output (commitment index used to traverse the prefix tree). |
| `auditor.batch-size`                                  | yes                                              | The maximum number of updates that the key transparency service should return in a single response. This value should be less than or equal to 1000.                                                                                                                                        |
| `auditor.interval`                                    | no                                               | The time interval at which the auditor job should run to process key transparency updates. Defaults to 1 minute.                                                                                                                                                                            |
| `auditor.signature.interval`                          | no                                               | The interval at which the auditor should send a signed tree head to the key transparency service, in duration. Defaults to 1 hour.                                                                                                                                                          |
| `auditor.signature.page-size`                         | no                                               | The interval at which the auditor should send a signed tree head to the key transparency service, in number of updates. Defaults to 1,000,000.                                                                                                                                              |
| `grpc.channels.key-transparency.address`              | yes                                              | The address of the key transparency service.                                                                                                                                                                                                                                                |
| `storage.dynamodb.region`                             | Exactly one `storage.<type>` must be specified   | The AWS region of the DynamoDB table used to store auditor state.                                                                                                                                                                                                                           |
| `storage.dynamodb.table-name`                         | Exactly one `storage.<type>` must be specified   | The name of the DynamoDB table used to store auditor state.                                                                                                                                                                                                                                 |
| `storage.file.name`                                   | Exactly one `storage.<type>` must be specified   | The name of the file used to store auditor state.                                                                                                                                                                                                                                          |

Contributing bug reports
------------------------

We use [GitHub][github issues] for bug tracking. Security issues should be sent to <a href="mailto:security@signal.org">security@signal.org</a>.

Help
----

We cannot provide direct technical support. Get help running this software in your own environment in our [unofficial community forum][community forum].

License
-------

Copyright 2025 Signal Messenger, LLC

Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html


[github issues]: https://github.com/signalapp/key-transparency-auditor/issues
[community forum]: https://community.signalusers.org
