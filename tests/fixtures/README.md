# Fixtures

Synthetic files used by the `sensitive-data-detector` test suite. Each one
exists to trigger a specific detection pattern.

## Layout

- `clean/`: files with nothing sensitive in them. The scanner should
  return zero findings here.
- `leaks/`: strings that match critical patterns (publicly published
  AWS and GitHub example keys, the canonical jwt.io JWT, a PEM block
  with fake content in the middle, assignments with obvious
  placeholders).
- `openshift/`: a pull-secret in its real format, with auth blobs whose
  base64 decodes to `user:pass` and `test:test`.

## Heads up

These files will set off any secret scanner. That is by design. They
exist precisely to match patterns so the tests can assert the detector
catches them.

The values in here are:

- example keys published by AWS in their own documentation, which grant
  access to nothing;
- valid provider prefixes followed by obvious placeholders (`FAKE`,
  `TEST`, `EXAMPLE`);
- the jwt.io demo JWT, only valid against the public demo key
  `your-256-bit-secret`;
- base64 strings that decode to trivial values like `user:pass`.

If an external scanner flags any of these, mark the alert as "test
fixture" or "false positive". Nothing in this directory is a real
credential.
