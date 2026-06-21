# Roadmap

This roadmap starts with governance only. Security content starts after
Milestone 0 is complete and the repository has validation and CI.

## Milestone 0: Project Governance

Goal: establish a small, reviewable operating model for the security governance repository.

### Issues

1. [#1 Create security governance documentation](https://github.com/Shoko-official/llm-security-governance/issues/1)
2. [#2 Add issue and PR templates](https://github.com/Shoko-official/llm-security-governance/issues/2)
3. [#3 Add minimal validation, CI, and folder structure](https://github.com/Shoko-official/llm-security-governance/issues/3)

### Execution Order

1. Complete issue #1 before templates or validation.
2. Complete issue #2 before content changes.
3. Complete issue #3 before security content.

No security content should be added during Milestone 0.

## Acceptance Criteria

Milestone 0 is complete when:

* repository role is documented;
* roadmap exists;
* contribution and review rules exist;
* issue and PR templates exist;
* minimal validation commands exist;
* minimal CI exists;
* initial folders exist;
* no security content has been added.

## Later Milestones

Expected sequence:

1. Define a minimal security policy and risk taxonomy schema.
2. Implement unsafe tool call detection filter rules.
3. Add simulated prompt injection check filters.
4. Implement validation rules checking compliance logs.
5. Create validation for security checks.
6. Connect security check results to agent runtime validations.

Any change to security parameters, risk definitions, or evidence rules must happen in a
dedicated issue.
