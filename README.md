# habuAI-eval-runner (PUBLIC, synthetic-only)

This is a bootstrap TEMPLATE for a new PUBLIC GitHub repository. Source files live temporarily in haji84/habuAI-private PR #136 under docs/qa/eval-bootstrap/public-runner until the user creates the target repository.

## Goal and hard limits

Run one frozen Qwen2.5-Coder 7B model on at least 40 **genuinely new** synthetic Python/JavaScript review cases supplied by a separate custodian. GitHub Actions runs on standard ubuntu-24.04 (public standard runners have no private-account monthly minute usage). The Private vault has **zero** Actions workflows.

This public repository MUST NOT contain actual Habu capture data, GPS, GPX, private labels, fixed witness inputs/results, signing keys, decryption keys, access tokens, or private-repository checkout instructions. It must NEVER fetch or checkout the Private vault. Model text is untrusted.

## Required files

- public_packet_guard.py: validate original signed-public-case envelope structure and exact source SHA *without* a private HMAC key.
- run_public_eval.py: no-secret read-only prompt collector. Writes public synthetic model answers and hashes to first-run Actions logs, not artifacts or a repository write.
- tests/test_public_runner.py: pure mock fixtures. These DO NOT form a true new assessment.
- .github/workflows/evaluate.yml: manual-only Qwen CPU workflow. Nothing triggers from ordinary pushes.
- cohort/public-packet.json: only the signed **public** packet generated AFTER a separate, independently controlled custodian seals the private assessment. DO NOT commit a dummy pack and call it unseen.

## Steps to activate once the proper custodian exists

1. Owner creates haji84/habuAI-eval-runner Public with a README on the main branch. Do not select a paid/larger runner.
2. Copy these source templates and tests. Unit tests run locally with Python 3.12 and no models or keys. Do not enable workflow until the independent evaluator completes freezing and secure custody.
3. Developer freezes the exact Habu AI implementation HEAD, full model digest, prompt, runner, source, scorer, witness adapter and thresholds. Record SHA-256 of the complete frozen manifest **before** a new private case is generated.
4. Independent custodian in another access domain creates and verifies at least 40 completely fresh synthetic cases; stores label/required result/input and witness evidence in an encrypted independent vault; exports only a signed PUBLIC packet to this repo.
5. Commit that public packet exactly and calculate its SHA-256 from the bytes. The raw public packet is openly readable and contains NO answers or labels. The runner's preflight verifies exact bytes, 40+ cases, Python/JS balance, canonical patches and no answer fields before spending CPU time.
6. Trigger Actions > Habu sealed synthetic Qwen7B one-shot evaluation > Run workflow, providing the exact public packet SHA-256 and previously frozen manifest SHA-256. Standard public runner only; read-only GitHub token and no persisted credentials, artifacts, secrets or external AI.
7. Preserve **the first run ID and its entire stdout response ledger**. The independent custodian must verify all response hashes against the first-run log and sign the predictions BEFORE opening hidden answers.
8. Only after prediction freeze may an independent semantic reviewer compare against independently executed fixed witnesses. A verified source quote is not enough: model claims need actual reproducible input/output proof. No same-author self-approval.

## Why a Private vault is STILL necessary

Public review prompts need to be public to use free hosted CPU. The correct answers must remain inaccessible until Qwen answers are frozen. A separate **account or access-control boundary** is required. A Private repository merely owned by the same development account, especially if the development AI GitHub App can read it, does not establish independent custody.

If there is no actual separate custodian/key custody, the protocol returns UNSEALED_HOLD. A public test suite with fake keys and synthetic examples cannot replace a real independently sealed evaluation.

## Security and cost

The manual workflow is the only model trigger; a normal push causes no Qwen execution. The job has read-only contents permission and runs only in the expected repository/default branch; no vault checkout, GitHub secret, PAT, deployment, release, external model API, data upload, large runner, model promotion or PR approval. All 7B usage is bounded by a standard Ubuntu CPU job timeout. Model weights and Ollama installer are SHA-256-pinned; model identity/digest is checked at runtime.

All public GitHub Actions logs are PUBLIC; therefore they contain only already public synthetic code, model replies, hashes and errors. Never pass a human's capture/GPS files into the runner.

## Score and release

Precision >=95%, Recall >=80%, clean-case raw false alert <=5%, zero missed designated critical defects. Model answer parse/unknown is not a correct prediction. Claims not independently reproduced are not verified true positives. The first genuinely sealed cohort remains frozen on failure.

Even a green GitHub job is NOT production qualification. Owner-approved model promotion and main merge are separate Human Gates.
