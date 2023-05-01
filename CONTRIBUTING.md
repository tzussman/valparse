# Contributing to `valparse`

## Issues

Feel free to open an issue if you encounter a bug or if you'd like to request a
feature. Before you open an issue, please do the following:

-   Scroll through the [existing issues](https://github.com/tzussman/valparse/issues)
    to see if the issue already exists.

-   Ensure you've read all the documentation in the [README](README.md).

-   Use the issue templates provided.

## Development

### Installation

Make sure you have Python 3.8 or newer.

You can install `valparse` locally by running the following:

```sh
sudo make develop && make build && make install
```

If it was successfully installed, you should be able to run `import valparse`
in the Python interpreter.

### Testing

To run the tests, run `make test` or `make coverage` (for coverage report) at
the top-level directory.

### Linting and formatting

Run `make lint` at the top-level directory to lint, and `make format` to
format.

### Pull requests

To make changes, create a pull request. Before opening a PR, you must do the
following:

- [ ] Test your code and ensure that it works as expected. If necessary, provide
      unit/integration tests for the code you're adding.

- [ ] Run the preexisting tests to ensure backwards compatibility.

- [ ] Lint and format the code.

- [ ] Open a PR, including a description of what your change does and why it
      should be merged.

- [ ] [Link your PR to an issue](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue)
      if you are solving one.

- [ ] Select the option to [allow maintainer edits](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/allowing-changes-to-a-pull-request-branch-created-from-a-fork)
      so the branch can be updated for a merge.


