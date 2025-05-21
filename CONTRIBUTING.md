# Contributing guidelines

We welcome contributions from everyone. To become a contributor, follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Make your changes.
4. Submit a pull request.

### Contributing code

When contributing code, please ensure that you follow our coding standards and guidelines. This helps maintain the quality and consistency of the codebase.

## Pull Request Checklist

Before submitting a pull request, please ensure that you have completed the following:

- [ ] Followed the coding style guidelines.
- [ ] Written tests for your changes.
- [ ] Run all tests and ensured they pass.
- [ ] Updated documentation if necessary.

### License

By contributing to this project, you agree that your contributions will be licensed under the project's open-source license.

### Coding style

### Testing

All contributions must be accompanied by tests to ensure that the code works as expected and does not introduce regressions.

#### Running unit tests
To creat a virtual environment, use the following command:
```sh
python -m venv venv && source venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt --upgrade && pip install -r test/test.requirements.txt --upgrade
```

To run all the unit tests locally, use the following command:
```sh
PYTHONPATH=src:test python -m pytest --color=yes test/*_unit.py
```
Unit tests also run automatically on every push using a dedicated workflow.

#### Running integration tests
To run integration tests locally, you first have to add API keys to your environment. You can do it by creating evn files under the config dir: 

aws.env.list
```
AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY
AWS_SECRET_ACCESS_KEY=YOUR_SECRET_KEY
AWS_REGION=YOUR_REGION
```
Then, to run all the integration tests locally, use the following command:

```sh
PYTHONPATH=src:test python -m pytest --color=yes test/*_integration.py
```

### Building docker image and using it
To build the docker image, use the following command from the root of the repository:
```sh
docker build -t dd-hoenypot .
```
To run the docker image, use the following command:
```sh
docker run -it --rm --name dd-honeypot -p 5000:80 -v $(pwd)/test/honeypots:/data/honeypot dd-hoenypot
```
explanation of the command:
- `-p 5000:80`: Map port 5000 on the host to port 80 in the container. You add additional ports if needed.
- `-v $(pwd)/test/honeypots:/data/honeypot`: Mount the local directory `test/honeypots` to `/data/honeypot` in the container. This allows you to access files in the container from your host machine. You can change the path to any other directory you want to mount.

### Version publication

Before publishing a new version, make sure the main branch is up-to-date, for example push changes from the dev branch to the main branch:
```sh
git switch dev
git pull
git push origin dev:main
```
Monitor the workflow to make sure tests are passing and then move to the version update.

```sh

The versions of the projects are managed using git tags. To publish a new version, make sure the main branch is up-to-date and create a new tag with the version number:
```sh
git tag -a v0.1.0 -m "Release 0.1.0"
git push --tags
```
Workflow will automatically publish the new version to the Docker repository under github container registry.

### Issues management

If you find a bug or have a feature request, please create an issue in the GitHub repository. Provide as much detail as possible to help us understand and address the issue.

We will review your issue and respond as soon as possible. Thank you for helping us improve the project!
