# ANVIL CLI image: lint / test / scan / convert Sigma rules.
#   docker run --rm -v "$PWD:/work" -w /work ghcr.io/rakshit-737/anvil:<tag> lint --rules rules
# Without a mount it runs against the bundled rules/ and examples/ in /opt/anvil.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE MANIFEST.in ./
COPY anvil ./anvil
RUN pip wheel --no-cache-dir --wheel-dir /wheels ".[sigma,evtx]"

FROM python:3.12-slim
RUN useradd --create-home --uid 10001 anvil
RUN --mount=type=bind,from=build,source=/wheels,target=/wheels pip install --no-cache-dir /wheels/*.whl
COPY --chown=anvil:anvil rules /opt/anvil/rules
COPY --chown=anvil:anvil examples /opt/anvil/examples
USER anvil
WORKDIR /opt/anvil
ENTRYPOINT ["anvil"]
CMD ["--help"]
