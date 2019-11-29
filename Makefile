.PHONY: publish, clean

devinstall:
	pip install -r requirements-dev.txt
	pip install -e .

test:
	pytest tests/unit

check:
	flake8 test/ src/

prcheck: check test


build:
	python setup.py sdist bdist_wheel

publish:
	twine upload dist/*

clean:
	rm -r build dist
