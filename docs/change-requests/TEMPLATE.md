# CR-<your-agent-id>-<slug>

**Filed by:** A<n> (`godwit-<package>`)
**Against:** `godwit-contracts` / `<other package>`
**Status:** open

## The problem

What you tried to do, and what the contract made impossible or ambiguous. Be concrete:
the type, the field, the call site. If two readings of a docstring are both defensible,
say what both of them are.

## Why it matters

What breaks, or what you had to do instead. If the answer is "nothing breaks, it is just
awkward", say that honestly — it changes the priority.

## The smallest sufficient change

Not the change you would most enjoy. The smallest one that unblocks you. Give the exact
field or signature.

```python
# current
...

# proposed
...
```

## Who else this affects

Every package that touches the type. Name them. If it changes `segment_key` or
`probe_key`, say so loudly: that is a migration of every stored key, not a patch.

## What I did instead

The implementation against the contract as written, and the `xfail` test:

```
packages/godwit-<package>/tests/test_<x>.py::test_<y>
@pytest.mark.xfail(reason="CR-<your-agent-id>-<slug>")
```

## Decision

_Left blank by the filer. A human fills this in._
