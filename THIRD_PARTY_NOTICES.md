# Third-Party Components

VAPT Sanitizer v1.0.0 declares the following Python runtime dependencies:

| Component | Version | License |
| --- | ---: | --- |
| PyYAML | 6.0.3 | MIT |
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause |

The Burp extension is compiled against PortSwigger's Montoya API as a `compileOnly` dependency; that API is not bundled into the extension JAR by this project.

The bundled Gradle bootstrap downloads Gradle 8.14.3 from the official Gradle distribution service and verifies the pinned SHA-256 before execution. The Gradle distribution itself is not stored in this repository.

This file is informational and does not replace the license texts or notices supplied by the respective upstream projects.
