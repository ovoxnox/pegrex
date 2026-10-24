---
name: pegrex-grammar
description: Engineer lpegrex grammars: lint, induce from examples, lift/lower via IR, extract from upstream. Use when writing a new grammar or fixing grammar bugs.
---

# grammar engineering

## The corpus
13 formats in examples/: json, c11, sexpr, ini, csv, url, go-subset,
rust-subset (paste-ready), vyper-subset, agent(.work), mir, mlir + bench-mlir.

## Workflow
    python pegrex.py lint <file.gram>            # hygiene (run FIRST)
    python pegrex.py induce <pos.txt> [--negatives F] [--out g.gram]
    python pegrex.py extract <upstream.lua> <out.gram>   # verbatim pull

## Debugging discipline (the project's iron rules)
1. The compiler's error labels name the EXACT position and expectation —
   read `L<n>:C<m>` before changing anything.
2. Fatal-@ poison: `@x` inside a `*`/`+` repetition THROWS instead of
   failing — the linter catches this; never hand-patch past it.
3. Whole-file rewrites over string patches — incremental sed-style edits
   on grammar text are the #1 source of subtle breakage.
4. No external oracle for a new grammar? Use `pegrex.py induce` to grow
   the positive/negative corpus automatically.

## IR (programmatic grammar transforms)
    from pegrex.gramir import lift_grammar, lower, to_dsl
    irs = lift_grammar(rules)      # compiled patterns -> editable IR
    text = to_dsl(irs["Rule"])     # IR -> grammar-DSL text

