# LLM Security Governance

`llm-security-governance` defines the security policies, verifier checks, and compliance rules workspace for the
Modern LLM Systems 2026 / arXiv Report program.

This repository will organize prompt injection filters, unsafe tool call detection, risk taxonomy, and agent runtime safety policies.

It is not the research ledger, paper repository, RAG implementation, evaluation harness, inference benchmark, agent runtime, or memory layer.

## Repository Role

This repository owns:

* security and safety governance;
* verifier check policies and rule definitions;
* simulated prompt injection vectors and check rules;
* compliance validation and CI once introduced;
* paper-facing security chapters and evaluation support when backed by approved evidence.

The central project board is:

* [Modern LLM Systems 2026 / arXiv Report](https://github.com/users/Shoko-official/projects/4)

## Current Scope

Milestone 0 is limited to governance.

Included:

* repository scope;
* roadmap;
* contribution rules;
* review rules.

Out of scope:

* actual firewall implementation;
* hardware execution isolation;
* final paper drafting;
* agent memory, RAG indexing, or evaluation dataset definition.

## Evidence Policy

Future security claims must reference approved research ledger material or stay
clearly marked as unresolved planning notes.

Unsupported claims must not be used as paper-ready security content.

## Figure Policy

Allowed source formats:

* Mermaid text diagrams for workflows, architecture maps, dependency graphs, and
  concept maps.
* Python-generated images for visualizations that are not practical in Mermaid.

Not allowed by default:

* web images;
* screenshots unless explicitly approved;
* hand-drawn images;
* Figma, Canva, or PowerPoint exports;
* manually authored complex SVGs;
* binary figures without clear source;
* orphan figures.

## License

This repository is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
