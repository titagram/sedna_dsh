# Adding knowledge to the base

The seed in this repository is a starting point. This is how it stops being the whole base.
Everything below is engine behaviour, verified by reading the vendored source; the ingest
write path itself has **not** been executed end to end yet, and the places where that matters
are marked.

## There is no command

The engine declares no `console_scripts`: there is no `sedna` binary. Every stage is a Python
API call, and the retrieval driver (`plugin/sedna/driver.py`) speaks one JSON request per
operation:

| stage | what actually does it | reachable from the driver |
|---|---|---|
| ingest / classify | `DocumentLearningService.learn()` (`knowledge/learning.py`) | no — needs an LLM host |
| compile / materialize | automatic inside `learn()` (extract → critic → repair → materialize → store) | no |
| verify / index | `RetrievalMaintenanceService.rebuild()` | yes: `{"op":"maintenance","args":{"operation":"rebuild"}}` |
| promote | engagement-derived case studies only (`sedna_manage_engagement`) | no |

An LLM is needed **at ingest only**. Retrieval, maintenance, audit and engagements run
without one — the driver imports no LLM host. That is the single most useful fact about
running this in a container: the provider is needed when you *teach* the base, not when you
*ask* it.

The ingest model speaks two APIs and picks between them from the URL alone
(`knowledge/semantic/ollama_host.py`): `/api/chat` (native, a local Ollama) when the URL is
anything else, and `/v1/chat/completions` when it contains `ollama.com` or `/v1`. So an
Ollama cloud endpoint, an OpenAI-compatible gateway and a local model are all reachable by
changing `SEDNA_OLLAMA_URL` — no adapter to write.

## Which model can do this

Ingest asks the model for JSON conforming to a schema, and the engine sends that schema as the
structured-output constraint (`knowledge/semantic/ollama_host.py`). Whether the constraint is
*honoured* is a property of the model and of how it is served, not of the request — measured on
one machine, same prompt, same schema:

| served as | schema as `format` | `format: "json"` | OpenAI-compatible `response_format` |
|---|---|---|---|
| a local model | valid JSON | valid JSON | n/a |
| an Ollama Cloud model | **prose, constraint ignored** | valid JSON | **prose, ignored** |

So a cloud model can be perfectly capable and still be unable to do the one thing ingest needs,
because structured output is enforced by the local runtime and a hosted model ignores the
constraint. Two consequences:

* **`format: "json"` is the portable request**, not the schema. A model that ignores the schema
  still honours plain JSON mode; a model that honours both is unaffected by asking for less.
* **A refused constraint is not an error here.** The host parses the answer, falls back to
  salvaging the last balanced `{...}` from the text, and returns `parsed=None` when there is
  none — no exception. A model answering in prose therefore produces an ingest that fails
  quietly, which is the worst shape a failure can have.

Whatever chooses the ingest model must therefore validate the answer against the schema it
asked for and say so when the model did not comply, rather than forwarding a null parse into
the compiler and hoping the silence means success.

## The path is part of the input

A source is classified by its **physical path**, not only by its content: it must sit under
a corpus-family marker such as `write-ups/machines/<machine>/<machine>.md`
(`knowledge/classifier.py`). A file placed anywhere else is quarantined as
*foundation* material and becomes unretrievable — **silently**. The content also needs at
least two substantive headings and one code block.

Two consequences worth designing around, and both are the reason a bare `learn()` call is a
poor user interface:

* the way to add knowledge is a **stable inbox directory** whose layout carries the marker,
  not "point it at any file";
* a quarantined source must be **reported loudly**, with the reason. A base that quietly
  ignores what you gave it is worse than one that refuses it.

`source_id` is path-addressed — `uuid5("sedna:" + relative_path)` — not content-addressed.
Re-adding the same relative path from a different root is rejected
(`source_namespace_collision`), so the inbox root must not move.

## The minimal path for one source

1. Back up first: `scripts/backup_kb.sh backup --full`.
2. Place the file so its path carries the marker, inside the stable inbox root.
3. Ingest it (this is the step that needs a model, and it is not free: extract, critic and
   repair each call one).
4. The retrieval index rebuild is automatic at the end of ingest — but it is mandatory in
   effect, because until it exists every lane answers `no_applicable_knowledge`.
5. Confirm: an audit must report `succeeded: true` and `rebuild_required: false`.
6. Trace the result: the retrieval candidates carry only `artifact_id`, `artifact_type` and
   `label` — **provenance is on the artifact**, not on the candidate. `{"op":"artifact"}` is
   what shows `source_refs`, and therefore what proves your source is the one that answered.

## After a restore, and when it goes wrong

* A restore in the default (non-`--full`) mode restores `manifests/` and `semantic_bundles/`
  and **drops `quarantine/`**. A source with no bundle and no quarantine record invalidates
  the entire corpus, and the repository is fail-closed, so every lane then answers nothing.
  Restore with `--full`, or restore the quarantine trees by hand, then rebuild and audit.
* A failed audit or rebuild writes `indexes/.retrieval.sqlite.unavailable`. While that marker
  exists the lanes are blocked and the base looks empty. `compose/bootstrap-kb.sh` treats it
  as what it is — a missing index — and rebuilds.
* If the base answers nothing, check the audit before believing it: `succeeded: false` with a
  source count of zero means a corpus problem, not an absence of knowledge.
