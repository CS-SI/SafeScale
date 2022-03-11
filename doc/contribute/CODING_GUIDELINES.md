# CODING GUIDELINES

This file list the guidelines to use when you want to contribute to SafeScale code.

## error messages

In general, follow the GOLANG coding guidelines, in particular:

- Don't use capitalized error messages
- Don't use punctuation at the end of the error messages

## code documentation

As much as possible, follow the [godoc documentation tool formalism](https://blog.golang.org/godoc-documenting-go-code).

## code indentation

- uses tab for indentation, with a tab size of 4 spaces

## naming conventions

### variables

Do not use variable names identical to type names, to avoid confusion.

### `unsafe` prefix on function names

You may find some function names prefixed with `unsafe`. In general, there is a counter-part without the prefix for public use (ie callable outside the package):

  - Public function/method is in charge of parameter validation and needed locking to ensure concurrent accesses without data races
  - `unsafe` function/method does the real work without taking care of parameter validation (in most case) and concurrent accesses

Inside its package, `unsafe` function is useable but in full knowledge of the risks:
  - parameters used in `unsafe` function calls must have been validated before the call
  - lock consideration is responsibility of the caller of `unsafe` function

If the risks are not well understood, you may encounter issues (nil dereferences, deadlocks, data races, ...)

Example:
  - in `lib/utils/data/cache/cache.go`:
    - `cache.ReserveEntry(...)` calls `cache.unsafeReservedEntry()` after having validated parameter and set locking.
    - `cache.unsafeReserveEntry(...)` do the work unconditionnaly

---

Good documentation is an everyday job (we still have to respect this mantra ourselves ;-) ).

