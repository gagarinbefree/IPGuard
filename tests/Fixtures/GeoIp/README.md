# Synthetic MMDB fixtures

These files are synthetic test data, not a production geolocation database.

Source: [MaxMind-DB](https://github.com/maxmind/MaxMind-DB/tree/255b9a8b8a692d70dcaef31dc2ca44fa7ce50ece/test-data), commit `255b9a8b8a692d70dcaef31dc2ca44fa7ce50ece`.

Copyright (c) 2013-2026 MaxMind, Inc. Used under the MIT option of the upstream dual license; see [LICENSE-MIT](LICENSE-MIT).

`GeoIP2-Country-Test.mmdb` SHA-256: `FC12D6470B35B70BD3E4534DD433D3E262A6C73F7682F85C344E832D4190F02B`.

`GeoIP2-City-Test.mmdb` tests rejection of an unsupported product. Expected country records are taken from the upstream `source-data/GeoIP2-Country-Test.json`. In particular, `81.2.69.160` has country `GB` and registered country `US`; `149.101.100.1` has country `US` and registered country `GB`.
