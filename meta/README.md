# provenex

A meta-package for [Provenex](https://provenex.ai). `pip install provenex` installs [`provenex-core`](https://pypi.org/project/provenex-core/), the actual library.

```bash
pip install provenex
# is equivalent to
pip install provenex-core
```

Use `provenex-core` directly if you want explicit control over the version. Use `provenex` if you want the canonical install command.

## Why a separate package?

Reserving the bare `provenex` name on PyPI so it can't be squatted. The `import provenex` Python module ships from `provenex-core`; this package is purely a name placeholder + dependency redirect.

For everything else — docs, the library itself, source code, examples — see [github.com/provenex/provenex-core](https://github.com/provenex/provenex-core).

## License

MIT.
