.PHONY: integration-test-base

integration-test-base:
	env DOCKER_BUILDKIT=1 docker build -t matchhostfsowner-integration-test-base -f Dockerfile.integration-test-base .
