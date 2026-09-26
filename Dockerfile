# ANVIL CLI image: lint / test / scan / convert Sigma rules. Mount rules and telemetry at /work.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY anvil ./anvil
RUN pip wheel --no-cache-dir --wheel-dir /wheels ".[sigma,evtx]"

FROM python:3.12-slim
RUN useradd --create-home --uid 10001 anvil
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
COPY --chown=anvil:anvil rules /opt/anvil/rules
COPY --chown=anvil:anvil examples /opt/anvil/examples
USER anvil
WORKDIR /opt/anvil
ENTRYPOINT ["anvil"]
CMD ["--help"]
