import nox


@nox.session()
def clean(session: nox.Session):
    session.install("coverage")
    session.run("coverage", "erase")


@nox.session()
def py3(session: nox.Session):
    session.install(
        "-e",
        ".",
        "pytest",
        "pytest-cov",
        "pytest-timeout",
        "pytest-xdist",
        "coverage",
        "psycopg2",
    )
    session.run(
        "pytest",
        "--cov=vault",
        "--cov-append",
        "-n=4",
        "--timeout=5",
    )


@nox.session()
def report(session: nox.Session):
    session.install("coverage")
    session.run("coverage", "html")
    session.run("coverage", "report", "--fail-under=80")
