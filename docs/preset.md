# Making a DSH agent use this stack

This repository installs the *capabilities*: the `sedna_*` tools (mounted host-wide
through `~/.dsh/cordis.patch.yml`), the skills (in `~/.agents/skills/`), the engine, the
knowledge base and the memory daemon. Capabilities are not a personality: what an agent
*does* with them comes from the preset its session mounts.

## Why there is no bundled preset

It would be easy to ship one, and it would age badly. A preset is a **complete**
composition — it replaces the shipped `standard` preset rather than extending it — so a
copy of standard's three hundred rows lives in this repository and drifts with every
DSH release. A stale copy is worse than no copy: it silently withholds new tools and
capabilities from the agent that mounts it.

Instead, three small edits to a preset you already have. Copy one first:

```
# in a DSH session
the agent runs agentPresets.copy('standard', 'pentest') and then edits the copy
```

or, by hand, copy the directory under `${DSH_HOME:-$HOME/.dsh}/.agent-presets/`.

## 1. the Sedna tools

If the installer wrote the host row, every session already has the `sedna_*` tools and
there is nothing to add. To mount them for **one** preset instead (so other sessions do
not see them), add this row to the preset's `agent.cordis.yml`:

```yaml
- id: sedna
  name: !!js "process.getBuiltinModule('node:url').fileURLToPath(new URL('../../../plugins/sedna/index.mjs', baseUrl))"
  config:
    knowledgeRoot: !!js "process.getBuiltinModule('node:path').join(process.env.HOME, '.dsh', 'knowledge', 'sedna')"
```

`baseUrl` is the preset's own directory — `.agent-presets/<id>/` — so the relative path
resolves to the installed plugin wherever the home directory is. The python, driver and
engine paths default to the layout the installer creates; set them explicitly if you
moved things.

## 2. the skills

The installer puts the three skills in the global skill root, where they are already
available. To keep them **with the preset** (so copying the preset copies its skills),
add:

```yaml
- id: skill-filesystem
  name: '@deepseek-ai/dsh-skill-filesystem'
  config:
    customSkillDirs:
      - !!js "process.getBuiltinModule('node:url').fileURLToPath(new URL('skills/', baseUrl))"
```

and put `sedna-cyber-workflow/`, `lab-pentest/` and `sedna-dsh-bridge/` under the
preset's own `skills/` directory (they are in this repository under
`preset/pentest/skills/`).

## 3. a persona that knows what the tools are for

The tools do not explain when to use them. A short prefix is worth more than a long
one; this is the one this stack was built around:

```yaml
- id: persona
  name: '@deepseek-ai/dsh-persona'
  config:
    prefix: |-
      You do authorised lab, HTB and CTF work only: never scan a public or third-party
      system, and never fetch a write-up without explicit authorisation for that case.

      Before offensive work, load the sedna-cyber-workflow and lab-pentest skills and
      follow the loop: authorise, declare the target, retrieve (the four lanes), scan,
      plan, record the decision, verify, promote.

      The Sedna knowledge base is verified, curated, fail-closed truth: use
      sedna_retrieve_knowledge with authorization_state="authorized" and the target in
      exact_targets, and it will tell you when it has a gap rather than inventing one.
      Hindsight is long-term, lower-precision memory: a candidate source, never the
      last word.

      Sanitise everything you persist. No flags, credentials, keys, cookies or tokens
      in reports, in memory, or in messages to another instance.
```

## Checking it

Mount-validation is the only real test — it composes the preset exactly as a session
start does and rejects a row whose package does not resolve, whose config is invalid,
that never activated, or that publishes a service outside an isolate realm:

```
# in a DSH session
the agent runs agentPresets.standingKeyFor('pentest') and reports what it returns
```

Then start a session on the preset and look at the tool list. If `sedna_retrieve_knowledge`
is there, the row mounted.
