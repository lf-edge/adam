# Automated Release Process Documentation

This document outlines the automated release process for the repository. Using GitHub Actions, we ensure consistent tagging, building, and publishing of artifacts to DockerHub and GHCR.
You can find workflows under `.github` directory


## Release Workflow Overview

The GitHub Actions workflow automatically:

- Builds Docker images for the release artifact in format v.X.Y.Z
- Publishes the images to:
  - DockerHub
  - GitHub Container Registry (GHCR)

## Automated Tagging and Publishing

1. Version Tagging

- Release tags follow the format vX.Y.Z, where:
  - X.Y are the major and minor versions.
  - Z is the iteration derived from the master branch.
- Tags are automatically generated and pushed to the repository.

2. Build and Publish Workflow

The GitHub Actions workflow:

- Detects the creation of a new tag (v*).
- Builds the Docker image for the tagged version.
- Pushes the image to both DockerHub and GHCR.

## Key Notes

### Secrets Configuration

DockerHub Credentials: Add the following secrets to your repository:
- RELEASE_DOCKERHUB_ACCOUNT
- RELEASE_DOCKERHUB_TOKEN

GitHub Token: Ensure GITHUB_TOKEN is available for pushing to GHCR.

Triggering the Release Workflow

- Create a new tag in the repository using the vX.Y.Z format:
    - git tag -a v0.0.57 -m "Release version 0.0.57"
    - git push origin v0.0.57

The workflow will automatically start upon detecting the tag.

## Verifying the Release

- DockerHub: Verify the image is listed under adam DockerHub repository: https://hub.docker.com/r/lfedge/adam
- GHCR: Verify the image is listed in the GitHub Packages section of adam repository: https://github.com/lf-edge/adam/packages
