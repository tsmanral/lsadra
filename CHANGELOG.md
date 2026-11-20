# Changelog

## [6.0.0](https://github.com/tsmanral/lsadra/compare/v5.0.0...v6.0.0) (2026-11-20)


### ⚠ BREAKING CHANGES

* the legacy Streamlit dashboard, its compose service and requirements/ui are removed. lsadra.ui.* imports still resolve through a deprecated alias.
* the legacy Streamlit dashboard and 'docker compose --profile legacy' are gone; use the React dashboard or the desktop app.

### Features

* add a dev container for one-click setup ([02d5610](https://github.com/tsmanral/lsadra/commit/02d56104dc9140f4647bd04237fef1a929ca61d7))
* add a dev container for one-click setup ([7d68dbb](https://github.com/tsmanral/lsadra/commit/7d68dbb01b12b585740f69479f05c88864f11f36)), closes [#114](https://github.com/tsmanral/lsadra/issues/114)
* **agent:** read-only CIS IG1 posture checks on Linux hosts ([752f01e](https://github.com/tsmanral/lsadra/commit/752f01eb19180ba5e9b07e6d7b05364ae2553496))
* **api:** authenticated /ws/alerts live alert stream ([1d01b40](https://github.com/tsmanral/lsadra/commit/1d01b409724297fb57de41bf9a093e9ef1596eda))
* **api:** authenticated /ws/alerts live alert stream ([e9c7928](https://github.com/tsmanral/lsadra/commit/e9c792835164f79c9de8d40057cdd3de79b18298))
* **bench:** add opt-in per-request tracing to the ingest benchmark ([4324c5a](https://github.com/tsmanral/lsadra/commit/4324c5abdd916aca711edd223f689d04047e4f0a))
* **bench:** ingest benchmark harness + committed baseline ([#54](https://github.com/tsmanral/lsadra/issues/54)) ([a00c250](https://github.com/tsmanral/lsadra/commit/a00c250e3f6cc8e79f458263a7fedc3b3a5f556b))
* **benchmarks:** detection bench with TPR per ATT&CK technique at fixed FPR ([c811833](https://github.com/tsmanral/lsadra/commit/c811833c41e5b0a8d97700e45b7fb3f093312727))
* **benchmarks:** detection bench with TPR per ATT&CK technique at fixed FPR ([a9d7748](https://github.com/tsmanral/lsadra/commit/a9d77480ec16b0309cdf3bfda17843e3b7e523c3))
* **bench:** replay production training through the canary-gated retrain path ([8e07351](https://github.com/tsmanral/lsadra/commit/8e07351b65a891b77b3c093d3606ba18ee9c7123))
* **bench:** replay production training through the canary-gated retrain path ([a165d56](https://github.com/tsmanral/lsadra/commit/a165d56abe1eef96e2ba44ce5c890649d98c8b71))
* **bench:** score Phase 1 challenger models next to today's layers ([a37f105](https://github.com/tsmanral/lsadra/commit/a37f105dda02cb69d40cbf6f71fd42ed46dc898e))
* **bench:** score Phase 1 challenger models next to today's layers ([feb87e4](https://github.com/tsmanral/lsadra/commit/feb87e4d2754ca62072a394ebf6ded2928dbbf59))
* **collectors:** add Rust Cargo workspace with journald and Windows Event Log agents ([2118670](https://github.com/tsmanral/lsadra/commit/2118670ab2e5fbd9de1b1ff518e5c0d00e1b4464))
* **collectors:** Rust agents for journald and Windows Event Log, plus the Linux agent stall fix ([c4f5849](https://github.com/tsmanral/lsadra/commit/c4f5849f98714a329e8dd43a21455a85ae0083f7))
* **dashboard:** show real data on the incident, investigate, response and feedback pages ([4fda177](https://github.com/tsmanral/lsadra/commit/4fda1778d0192877f4ff287f84346b1211543402))
* **dashboard:** show real data on the incident, investigate, response and feedback pages ([a2bf890](https://github.com/tsmanral/lsadra/commit/a2bf8903a9932347891a599b94b0a95a6fee530e))
* **demo:** labeled synthetic corpus + API-replay seeder (layers 1+2) ([#30](https://github.com/tsmanral/lsadra/issues/30)) ([73391c8](https://github.com/tsmanral/lsadra/commit/73391c8d9b9314196cd91a5b698a32fa87fab793))
* **deploy:** serve the React dashboard from docker compose ([c54a3ce](https://github.com/tsmanral/lsadra/commit/c54a3ce7123c6ffeef7c633aec9a5399244cbece))
* **deploy:** serve the React dashboard from docker compose ([da1a9d3](https://github.com/tsmanral/lsadra/commit/da1a9d38e51469f0b56ab4882bee68e8c88de0aa)), closes [#115](https://github.com/tsmanral/lsadra/issues/115)
* **desktop:** add Tauri tray app that runs the local server and shows the dashboard ([9724c7c](https://github.com/tsmanral/lsadra/commit/9724c7c634668160aa8459da8063361279276e0b))
* **detection:** add a Sigma rule layer in shadow mode ([d6236ed](https://github.com/tsmanral/lsadra/commit/d6236ed6ba03ffce8bdda68c632c22d43b3132d9))
* **detection:** add the ECOD shadow scorer over the wider feature set (ADR 0007 Phase 1) ([207524f](https://github.com/tsmanral/lsadra/commit/207524f5f47146b8dd88af959d49b32ec1dac8c9))
* **detection:** ECOD shadow scorer over the wider feature set (ADR 0007 Phase 1) ([d7830e6](https://github.com/tsmanral/lsadra/commit/d7830e61b229dc90a7652ddcecd084a7df57a4e6))
* **detection:** make scheduled scans raise alerts ([25be7dc](https://github.com/tsmanral/lsadra/commit/25be7dcbfd3d61b4c80dbc579f293cf5e74e3bd4))
* **detection:** retrain automatically as stored events grow ([1729dd9](https://github.com/tsmanral/lsadra/commit/1729dd9d8476f47262ea3bb6c9a257a6acb6799d))
* **detection:** retrain automatically as stored events grow ([dfc8883](https://github.com/tsmanral/lsadra/commit/dfc88834ae1f6454cd75b6797df7bfe5c2b7c700))
* **detection:** run one tested rule registry on the live path ([efdaf2c](https://github.com/tsmanral/lsadra/commit/efdaf2ce70916f4baddc7bda654dd38311ba5317))
* **detection:** run one tested rule registry on the live path ([e5ef6d0](https://github.com/tsmanral/lsadra/commit/e5ef6d0cd6472c9177483d00e144dd57e983438a))
* **detection:** run online detection off the ingest request path (S2-1) ([#56](https://github.com/tsmanral/lsadra/issues/56)) ([73f13e4](https://github.com/tsmanral/lsadra/commit/73f13e4558626cd29c06c2e5faa66ea0195963ed))
* **detection:** score host and user risk and open risk cases ([49bf519](https://github.com/tsmanral/lsadra/commit/49bf519e2ede174f2b5dcc6e899f90cc6cf172d0))
* **frontend:** stream dashboard alerts over /ws/alerts and drop the offline login ([406c0cb](https://github.com/tsmanral/lsadra/commit/406c0cbfadae3dc340d4a1168a563470ac2dfa74))
* **frontend:** stream dashboard alerts over /ws/alerts and drop the offline login ([e81e12b](https://github.com/tsmanral/lsadra/commit/e81e12bbb6f2f4c1e5618f331aff23899dc0956c))
* **ingestion:** freeze event schema v1 and enforce it at the boundary ([#53](https://github.com/tsmanral/lsadra/issues/53)) ([7757ca1](https://github.com/tsmanral/lsadra/commit/7757ca1ee6369cfaf305ae174b1236af314030a6))
* **intel:** two-tier threat intel with a signed, key-free bundle ([b4da543](https://github.com/tsmanral/lsadra/commit/b4da543af0e5be34402e38738bab3b36dd2f16d2))
* **jobs:** start the scheduler with the app and bound retention ([174fedb](https://github.com/tsmanral/lsadra/commit/174fedb808df382173e423fb3d4a377989d38b2a))
* **jobs:** start the scheduler with the app and bound retention ([9684fbc](https://github.com/tsmanral/lsadra/commit/9684fbc20272791317c3e16098b0697d323bd204))
* **llm:** add LLM-tier guardrails, a proposal-only action broker and a red-team corpus ([da21f8b](https://github.com/tsmanral/lsadra/commit/da21f8b0ab6ce10ea6f52a058b785a3ddcab747d))
* **models,llm:** model integrity, training controls and LLM guardrails (G-17, G-18, G-19, G-30) ([56a265f](https://github.com/tsmanral/lsadra/commit/56a265f6a13ba6219f6bc287aee4280c3496a97c))
* **models:** verify model files before loading and gate training behind a canary ([a946bd3](https://github.com/tsmanral/lsadra/commit/a946bd3e6c3ca8f74ba735fbd73b63d5b2621581))
* package the core with lsadra-server and lsadra-admin commands ([cc4547c](https://github.com/tsmanral/lsadra/commit/cc4547c4987b7cd2c4b5b0debf8b86382c295ce1))
* package the core with lsadra-server and lsadra-admin commands ([e9f9bce](https://github.com/tsmanral/lsadra/commit/e9f9bcefd87b5a8ce5ee9159823a22b67fec8e49))
* security governance docs, tiered retention, parser fuzzing, agent posture checks ([a8633be](https://github.com/tsmanral/lsadra/commit/a8633beac10cc28dfd5a9d4cdd77579324b4b253))
* **security:** R8 sanitizer for log-derived narrative fields ([#52](https://github.com/tsmanral/lsadra/issues/52)) ([0cc230f](https://github.com/tsmanral/lsadra/commit/0cc230f5d8b63c08f581865eb0329976618e34cf))
* **security:** revocable sessions, login hardening, audit trail and data-at-rest controls ([14b75df](https://github.com/tsmanral/lsadra/commit/14b75df6d04d20f972ebcf642c0c1bf9d32089d1))
* **security:** revocable sessions, login hardening, audit trail and data-at-rest controls ([77b0023](https://github.com/tsmanral/lsadra/commit/77b0023f89a81d4c2eacebab428279c99b2e57a3))
* **storage:** tiered retention, 30 days raw and 365 days for alerts ([22cefde](https://github.com/tsmanral/lsadra/commit/22cefde2a3e98b21dbc6acdb3a8cb95d950d51a3))


### Bug Fixes

* **agent:** stop one rejected batch from stalling the Linux agent ([e7917e5](https://github.com/tsmanral/lsadra/commit/e7917e528b24a814f8defbe7131755eda5716405))
* **api:** mark investigation SQL fragments for the S608 ratchet ([d1d010d](https://github.com/tsmanral/lsadra/commit/d1d010db8f1d8fc52f36c1585f7d608612bbfae5))
* **auth:** admin CLI explains missing server settings instead of crashing ([3ffdb55](https://github.com/tsmanral/lsadra/commit/3ffdb55aeeaa2828c23c0f186d41ad994f23b0e6))
* **auth:** create the first admin from the command line ([4b0c156](https://github.com/tsmanral/lsadra/commit/4b0c1561080c8360a11d2e7572e2853f3a315aa8))
* **bench:** count only tracked changes in the run's git.dirty flag ([f30b07c](https://github.com/tsmanral/lsadra/commit/f30b07cfa67effd65ef72837277f64865a4bdc45))
* **bench:** settle until detection is done and re-warm after a long settle ([431bc23](https://github.com/tsmanral/lsadra/commit/431bc2337fba3995c634f2e8995d2791908fd0b7))
* **bench:** start sparse-device steps on freshly verified device auth ([5e34b5f](https://github.com/tsmanral/lsadra/commit/5e34b5f679970db369a178550dde34cd7d46de80))
* **bench:** tolerate SQLite removing -wal/-shm while the harness sizes the db ([0f93479](https://github.com/tsmanral/lsadra/commit/0f934795130782dae69a26ca40528c51c9dcb935))
* **ci:** skip merge commits in the DCO check ([#36](https://github.com/tsmanral/lsadra/issues/36)) ([035623e](https://github.com/tsmanral/lsadra/commit/035623e0a504e56a6afbb62bb05de878d0312414))
* **dashboard:** KPIs and health work for non-admin users, no made-up numbers ([2bfa9bc](https://github.com/tsmanral/lsadra/commit/2bfa9bc40dda8587e3df1c9fa239111558102565))
* **dashboard:** KPIs and health work for non-admin users, no made-up numbers ([f9137b2](https://github.com/tsmanral/lsadra/commit/f9137b2b262019b36fec6cbd176877e224ed117b)), closes [#100](https://github.com/tsmanral/lsadra/issues/100) [#101](https://github.com/tsmanral/lsadra/issues/101)
* **dashboard:** never show canned demo data in real sessions ([1fcc38f](https://github.com/tsmanral/lsadra/commit/1fcc38f6249f8ca2ffafae8b6456021461af754d))
* **dashboard:** never show canned demo data in real sessions ([b93a031](https://github.com/tsmanral/lsadra/commit/b93a031692345257febdb6fa45ffe24ee02a70c4)), closes [#113](https://github.com/tsmanral/lsadra/issues/113)
* **dashboard:** show ingestion health whenever the API answers ([b1e7781](https://github.com/tsmanral/lsadra/commit/b1e7781ce9b2068ba0b4b1f9b3db9ceb61ffd863))
* **desktop:** only waive HTTPS for a server bound to loopback ([49ba8a5](https://github.com/tsmanral/lsadra/commit/49ba8a55f5fd64c7753cb8c788d14fc06ce97a32))
* **detection:** bound the lateral-movement check to its 30-minute window ([c5782df](https://github.com/tsmanral/lsadra/commit/c5782df29fd8fef911c8a1609d4447b8d3affa56))
* **detection:** bound the lateral-movement check to its 30-minute window ([4b9795d](https://github.com/tsmanral/lsadra/commit/4b9795d33903807250a4499e53342b86e6cb4fd3))
* **detection:** run the autoencoder on scikit-learn and drop PyTorch ([37d11b7](https://github.com/tsmanral/lsadra/commit/37d11b71954408d956972a45d259de2eb4e5ff89))
* **detection:** stop labelling unmatched anomalies T1190 and alerting on every event ([3f57f7a](https://github.com/tsmanral/lsadra/commit/3f57f7accbf6dcecf0316f712a7e9fa9f0b87acd))
* **detection:** stop labelling unmatched anomalies T1190 and alerting on every event ([18045a6](https://github.com/tsmanral/lsadra/commit/18045a6a77be8fca38ad0491ebdb31ea7c9b552f))
* **detection:** use a bound parameter for the failed-login filter ([afbda2d](https://github.com/tsmanral/lsadra/commit/afbda2dcc1065f64510bdfd845bc2da7a82058c8))
* harden online detection against malformed event input ([60d4d87](https://github.com/tsmanral/lsadra/commit/60d4d8745b090bc1af980d600ba8144ff04e8936))
* harden online detection against malformed event input ([1993938](https://github.com/tsmanral/lsadra/commit/199393856342478edd019d9e0aa8cef02e8ac226))
* **ingestion:** re-verify cached device keys in the background before they expire ([be213b6](https://github.com/tsmanral/lsadra/commit/be213b67518aaaefe672be11e9b19107905d1967))
* **ingestion:** remove the p99 tail from device auth and from detection's GIL use ([9917359](https://github.com/tsmanral/lsadra/commit/99173598f5ccdd844ee1396e62ac82f3e9846ee5))
* **intel:** keep signed bundle files byte-exact on Windows checkouts ([cf0bece](https://github.com/tsmanral/lsadra/commit/cf0becee4e6a4eaf353938ac488a4520137dcf7a))
* **intel:** log swallowed errors in geo reader close and trusted key load ([086dcb5](https://github.com/tsmanral/lsadra/commit/086dcb575701a098c9244e8d3c2c0004273dda14))
* **intel:** remove simulated threat-intel scores and third-party geo lookups ([73614f2](https://github.com/tsmanral/lsadra/commit/73614f2a2648d9e5caef7251c0e19029ca7899be))
* **models:** leave labelled attack events out of training ([9f14b81](https://github.com/tsmanral/lsadra/commit/9f14b816b1e25f1e1d10fb9fc9e6e46213bcb967))
* **models:** leave labelled attack events out of training ([d8613f8](https://github.com/tsmanral/lsadra/commit/d8613f897ee72b196c67df46e8c2afa61b3595c2))
* **security:** close default-install access gaps and verify agent installs ([b4f5b84](https://github.com/tsmanral/lsadra/commit/b4f5b84a510e7109db06b6242a5e57ac9d9a9f57))
* **security:** close default-install access gaps and verify agent installs ([03a10e1](https://github.com/tsmanral/lsadra/commit/03a10e14f455f465a4ee430c42a9525f9cbf9cbf))
* **security:** merge main and apply the password policy to every account path ([0e75b72](https://github.com/tsmanral/lsadra/commit/0e75b72a9d315b75576fcd35d032b035cc6b90d5))
* **server:** shorten the thread switch interval so detection cannot stall ingestion ([ac4da30](https://github.com/tsmanral/lsadra/commit/ac4da30ac3936127c2f81a20b91e218ca1421a5e))
* **storage:** FK-safe retention, connection release on error, model versioning ([#55](https://github.com/tsmanral/lsadra/issues/55)) ([5f5795a](https://github.com/tsmanral/lsadra/commit/5f5795a031708bc268f6590fc8e83125ba3a3086))
* **ui:** show LSADRA instead of the old Glass Sentinel name ([ad8aa94](https://github.com/tsmanral/lsadra/commit/ad8aa94ab9c3645b977576f5961d1f12df1e2413))
* **ui:** show LSADRA instead of the old Glass Sentinel name ([c1e4c86](https://github.com/tsmanral/lsadra/commit/c1e4c86089e9f94134b67038c6fc3d4a82d210b2))


### Performance

* **api:** run handler storage and bcrypt in the threadpool (S2-4) ([78fd09b](https://github.com/tsmanral/lsadra/commit/78fd09bb07200ab7136a2534572ffe9f32d22e24))
* **api:** run handler storage and bcrypt in the threadpool (S2-4) ([0328618](https://github.com/tsmanral/lsadra/commit/0328618513dc1b0a14aee1ad50382a8fa32f1052))
* **auth:** cache verified device credentials for a short TTL (S2-5) ([be2fae5](https://github.com/tsmanral/lsadra/commit/be2fae5a6135cfdf48ad5fe8f3a4989918aa5608))
* **auth:** cache verified device credentials for a short TTL (S2-5) ([1c44efa](https://github.com/tsmanral/lsadra/commit/1c44efa9f59b6919df514f2fe922f91920e145cb))
* **storage:** connection hygiene, executemany batch insert, one-transaction heartbeat ([#57](https://github.com/tsmanral/lsadra/issues/57)) ([addbf05](https://github.com/tsmanral/lsadra/commit/addbf056a77950bfb1b803f068a696ea6a60a474))


### Code Refactoring

* **auth:** move JWT handling from python-jose to PyJWT ([91537a0](https://github.com/tsmanral/lsadra/commit/91537a0f9e07fd634db78318f340b8bee382403e))
* **auth:** move JWT handling from python-jose to PyJWT ([9905c97](https://github.com/tsmanral/lsadra/commit/9905c978b709f12e9d08a4b30174eaec94d21842))
* keep the product version only in lsadra/__init__.py ([7684774](https://github.com/tsmanral/lsadra/commit/7684774bb08f1ce763c2f06e1e75bbf313e681a9))
* move the REST/WebSocket API to lsadra/api and remove the Streamlit UI ([3ae297a](https://github.com/tsmanral/lsadra/commit/3ae297a3b8c716b6316294359f63babe47f27134))
* move the REST/WebSocket API to lsadra/api and remove the Streamlit UI ([fb731d2](https://github.com/tsmanral/lsadra/commit/fb731d20cef80e7f402eb25f8076b730e96596e8))
* **storage:** share the event-insert statement between batch writers ([f96bc60](https://github.com/tsmanral/lsadra/commit/f96bc6027ef1c9af9a9665d4ff8cbc197b3fb053))


### Documentation

* add CLAUDE.md with the rules for AI coding agents ([1c03157](https://github.com/tsmanral/lsadra/commit/1c03157a4bc069b476c11d78a09be83339484730))
* add CLAUDE.md with the rules for AI coding agents ([f71315a](https://github.com/tsmanral/lsadra/commit/f71315a1ac2018aa50a080ef6200cc224b6d974e))
* add v6.0.0 release notes and document the release process ([cff667b](https://github.com/tsmanral/lsadra/commit/cff667bbf4cecc68050b641468411251774dcc46))
* **adr:** 0007 detection stack - rules, entity baselines, small ONNX models, bench-gated ([8218c71](https://github.com/tsmanral/lsadra/commit/8218c71ff9206f51b61a0a26027560a89cbe25a6))
* **adr:** 0007 detection stack - rules, entity baselines, small ONNX models, bench-gated ([3bd57b2](https://github.com/tsmanral/lsadra/commit/3bd57b2072cec990be53c684adcd8f7f8fb1ba34))
* **adr:** add 0005 Apple testing strategy (Proposed) ([#32](https://github.com/tsmanral/lsadra/issues/32)) ([86be984](https://github.com/tsmanral/lsadra/commit/86be98436aedc9aae142c150ed38a63a799a24df))
* **adr:** mark 0005 Accepted; 0003 superseded in part ([#34](https://github.com/tsmanral/lsadra/issues/34)) ([da8ed5e](https://github.com/tsmanral/lsadra/commit/da8ed5e2800e7cc684ee8f4de58f112f02162ad8))
* **adr:** point ADR 0007's bench links at GitHub so the strict docs build passes ([381fe11](https://github.com/tsmanral/lsadra/commit/381fe11258b551def7af059943a2e4c43acbc1ca))
* **adr:** record the Lite/Team line and enforce the import boundary ([3df38cf](https://github.com/tsmanral/lsadra/commit/3df38cf431d319e3143353d62247bb4a4b56d053))
* **adr:** record the Lite/Team line and enforce the import boundary ([37ef251](https://github.com/tsmanral/lsadra/commit/37ef251ff09a71441b5ba0e26e95a3f66f8aa21c))
* **bench:** commit the M1 D8 Linux runs after dropping PyTorch ([d6b0916](https://github.com/tsmanral/lsadra/commit/d6b0916b7b129ee45d81470fe0d3dec3f245e611))
* **bench:** commit the M1 D8 Windows gate run and fix stale training log markers ([6067af9](https://github.com/tsmanral/lsadra/commit/6067af96185d30dc6189921808b4143c2e902159))
* **bench:** describe the detection-aware settle ([1f87fa6](https://github.com/tsmanral/lsadra/commit/1f87fa6b77667262481b6fc147dfe23532ec086e))
* **contributing:** document DCO sign-off (D2 locked) ([#33](https://github.com/tsmanral/lsadra/issues/33)) ([c168f78](https://github.com/tsmanral/lsadra/commit/c168f78b202e6015eeb65e5bca24d0b39278eb02))
* cover the admin CLI in README, retake screenshots on fixed dashboard ([da29e18](https://github.com/tsmanral/lsadra/commit/da29e18556af2fc6ba99377a8f5b54d153ed81a2))
* describe the live rule registry and pinned ATT&CK map in the architecture docs ([e3ebca4](https://github.com/tsmanral/lsadra/commit/e3ebca4ad108b47e84d41bf47a50469fdb962e79))
* describe two-tier threat intel, local geolocation and key revocation ([2ed65fc](https://github.com/tsmanral/lsadra/commit/2ed65fc1a3dbe2cb3f4b5ac1085a5e57caa614fb))
* document two-tier threat intel, feeds and local geolocation ([b24271b](https://github.com/tsmanral/lsadra/commit/b24271b118ce776dc033942101136d217a659a44))
* drop the SHAP explainability claim the live pipeline does not deliver ([5c3a7ea](https://github.com/tsmanral/lsadra/commit/5c3a7eaa41736e41e815c1fea78ec07efc09d696))
* drop the SHAP explainability claim the live pipeline does not deliver ([ab8d161](https://github.com/tsmanral/lsadra/commit/ab8d1617dd217a25379ce70f2076925c8ff42f55))
* **env:** document LSADRA_WS_ALERT_QUEUE_SIZE ([e5b18d5](https://github.com/tsmanral/lsadra/commit/e5b18d5cf3cb68efa7664a1957f5d0bdb80b5f78))
* **env:** document the model integrity, training and LLM settings ([85e1778](https://github.com/tsmanral/lsadra/commit/85e177832edfa67b6f7289b90e05bba32deab704))
* link repo-root files by URL so the strict docs build passes ([f906598](https://github.com/tsmanral/lsadra/commit/f9065980019d18f322cdc5a3a842155ad135d20d))
* make the contributor quick start work on a fresh clone ([6942b7d](https://github.com/tsmanral/lsadra/commit/6942b7d52edd2b5c8e30edb9e8ceb717aa426984))
* make the contributor quick start work on a fresh clone ([6a78656](https://github.com/tsmanral/lsadra/commit/6a78656593cefe92d4ee7914f4121f64f7a1d7e9))
* **onboarding:** tighten the registration lock comment ([b61f3de](https://github.com/tsmanral/lsadra/commit/b61f3de05340e6c99b44bf12c7769c63e3c648f0))
* **readme:** bring README current and make freshness structural ([#31](https://github.com/tsmanral/lsadra/issues/31)) ([7fcd51a](https://github.com/tsmanral/lsadra/commit/7fcd51a68ad6dbd0479f8178bead9b209753e973))
* reflect the listener policy, model integrity, LLM guardrails and detection bench ([ec5caf1](https://github.com/tsmanral/lsadra/commit/ec5caf10da5d74038c90afaf61096651c5beb541))
* reflect the merged install, sign-up and compose changes in the architecture docs ([d57030c](https://github.com/tsmanral/lsadra/commit/d57030cfabc1f72f89b0d4af7999a9562751fbae))
* reflect the Rust collectors and product threat model now on main ([2eb3743](https://github.com/tsmanral/lsadra/commit/2eb37434d7a658e78ec26d68ca1d11482c3cc798))
* **release:** add [#167](https://github.com/tsmanral/lsadra/issues/167), [#172](https://github.com/tsmanral/lsadra/issues/172), [#173](https://github.com/tsmanral/lsadra/issues/173) and [#174](https://github.com/tsmanral/lsadra/issues/174) to the v6.0.0 notes ([43e6d69](https://github.com/tsmanral/lsadra/commit/43e6d692e3eeaa0c5110ef5dd272990239b66cdb))
* **release:** cover PRs merged since the last notes pass in v6.0.0 notes ([85527c7](https://github.com/tsmanral/lsadra/commit/85527c7b2b29560cf788d2e75138137df78563aa))
* **release:** cover the merged Phase 0 work in the v6.0.0 notes ([bf3e06b](https://github.com/tsmanral/lsadra/commit/bf3e06be6177e55df216a92eb030fff9b6104388))
* rewrite README with dashboard tour, verified setup and test steps ([fcb21fd](https://github.com/tsmanral/lsadra/commit/fcb21fda0809ab87a14f2147d02c85fff026af80))
* rewrite README with dashboard tour, verified setup and test steps ([049c9f2](https://github.com/tsmanral/lsadra/commit/049c9f2e45e0ca26d16578f3006625b25211ee54))
* say when an alert carries an ATT&CK technique ([600ec78](https://github.com/tsmanral/lsadra/commit/600ec7855fb9b9c9b7f91e507a8f790585f12cb4))
* **security:** threat model, operator incident runbook, SSDF and CRA page ([1cc85aa](https://github.com/tsmanral/lsadra/commit/1cc85aa2b8210ee2425df16a418b08fcfcfd1785))
* show a trained model on the Model Analytics screenshot ([82dd99d](https://github.com/tsmanral/lsadra/commit/82dd99dcc881ff768f6a572ee8f3d78b8d535f9e))
* show a trained model on the Model Analytics screenshot ([64d482a](https://github.com/tsmanral/lsadra/commit/64d482ad2f8deb2525bf6bd3428c074e8c033ff2))
* state DCO enforcement accurately now that it is real ([#37](https://github.com/tsmanral/lsadra/issues/37)) ([cbc329e](https://github.com/tsmanral/lsadra/commit/cbc329e6fd34468dbd26a770fdcf96075fefaac3))
* sync architecture docs, add C4 diagrams, agent-key threat model and strict docs build ([7b1d1ad](https://github.com/tsmanral/lsadra/commit/7b1d1ad5ac48a520d100a9737443eecad9a1a079))


### Build System

* **docs:** hash-lock the docs toolchain with the other requirements ([be97b2b](https://github.com/tsmanral/lsadra/commit/be97b2b01a8d0ae569bec9f890eea141ff671e45))
* hash-locked dependencies, hardened image and supply-chain CI ([d18d08e](https://github.com/tsmanral/lsadra/commit/d18d08efa45269977aab3911d76dafe59a992d5a))
* hash-locked dependencies, hardened image and supply-chain CI ([2350ad1](https://github.com/tsmanral/lsadra/commit/2350ad1785ba75d425f6e1da7527ec494923d2ef))
* lock CPU torch, add supply-chain tests, image build check and docs ([a7cf982](https://github.com/tsmanral/lsadra/commit/a7cf982ad7dd436b7e941857475f2803787d3988))

## Changelog

All notable changes to LSADRA are recorded here. From v6.0.0 on, entries are
generated by [release-please](https://github.com/googleapis/release-please)
from Conventional Commit subjects; readable notes for each release live in
[docs/releases/](docs/releases/). Earlier releases: see the
[GitHub releases](https://github.com/tsmanral/lsadra/releases) for v4.0.0,
v4.0.1 and v5.0.0.
